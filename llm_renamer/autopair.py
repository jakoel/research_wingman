"""
Auto-pairing: match functions between an OLD and PATCHED call graph without
BinDiff, then classify each pair as unchanged / noise / candidate.

Validated 2026-08-07 on a real old-vs-patched CLFS driver pair: 100% precision
and recall recovering the 3 real security-relevant functions (0 false
positives, 0 false negatives) against a known-correct BinDiff pairing, and
100% correct structural-fallback matching even when every name was blinded to
simulate a fully-stripped binary (see finding_autopair_validated memory for
the full methodology). Caveat: tested on one binary where old and patched are
a tight pair (~99% of functions byte-identical) -- size/basic-block-count are
strong discriminators there; a heavily-refactored/recompiled pair would see
more structural collisions.

Two-pass matching:
  1. Exact name match (skips sub_/nullsub_/j_/locret_/loc_/unknown_libname --
     those aren't real identity, they're "no name available").
  2. Structural greedy matching (size / basic-block-count / caller-count /
     Jaccard similarity of named-callee sets) for whatever is left unnamed on
     both sides -- this is what makes it work on stripped binaries, not just
     symbol-rich ones like the CLFS target it was validated against.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .call_graph import CallGraph, CallNode

_UNNAMED_PREFIXES = ("sub_", "nullsub_", "j_", "locret_", "loc_", "unknown_libname")

_NOISE_NAME_PATTERNS = [
    re.compile(r"^wil_details_"),
    # WIL feature-staging accessor boilerplate. Originally `Feature_\d+__private_`
    # (a bare numeric ID) but real builds use descriptive IDs too -- confirmed
    # 2026-08-11 against real ntfs.sys/http.sys pairs, e.g.
    # `Feature_Servicing_MSRC106366__private_IsEnabledFallback` and
    # `Feature_NVBugFixes2507__private_IsEnabledDeviceUsageNoInline` -- neither
    # matched the old digit-only pattern.
    re.compile(r"^Feature_\w+__private_"),
    re.compile(r"WCFA@EAA"),  # MSVC adjustor/virtual-thunk mangling marker
]

_STRUCTURAL_SCORE_FLOOR = 0.5  # cheap prefilter before the greedy assignment


def is_unnamed(name: str) -> bool:
    return any(name.startswith(p) for p in _UNNAMED_PREFIXES)


def is_noise_name(name: str) -> bool:
    return any(p.search(name) for p in _NOISE_NAME_PATTERNS)


def _named_callee_set(nodes: dict[int, CallNode], node: CallNode) -> frozenset[str]:
    # Unnamed (sub_/loc_-style) callees excluded -- their names embed the raw
    # address, which differs between old/patched binaries by construction, so
    # they can never contribute to a true Jaccard intersection, only inflate
    # the union (denominator), systematically deflating callee_sim exactly on
    # the stripped/partially-named binaries this fallback pass exists to
    # handle. Confirmed real gap 2026-08-16 (the function's own name promised
    # this filter but didn't apply it).
    return frozenset(
        nodes[a].name for a in node.callee_addresses
        if a in nodes and not is_unnamed(nodes[a].name)
    )


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _structural_score(nodes_old: dict[int, CallNode], old_node: CallNode,
                       nodes_patch: dict[int, CallNode], patch_node: CallNode) -> float:
    size_sim = 1 - abs(old_node.size_bytes - patch_node.size_bytes) / max(
        old_node.size_bytes, patch_node.size_bytes, 1)
    bb_sim = 1 - abs(old_node.basic_block_count - patch_node.basic_block_count) / max(
        old_node.basic_block_count, patch_node.basic_block_count, 1)
    callee_sim = _jaccard(_named_callee_set(nodes_old, old_node), _named_callee_set(nodes_patch, patch_node))
    caller_sim = 1 - abs(old_node.caller_count - patch_node.caller_count) / max(
        old_node.caller_count, patch_node.caller_count, 1)
    return 0.35 * size_sim + 0.25 * bb_sim + 0.30 * callee_sim + 0.10 * caller_sim


def auto_pair(nodes_old: dict[int, CallNode],
              nodes_patch: dict[int, CallNode]) -> tuple[list[tuple[int, int, str, float]], list[int], list[int]]:
    """Returns (pairs, unmatched_old, unmatched_patch).
    Each pair is (old_addr, patched_addr, match_method, confidence)."""
    patch_by_name: dict[str, list[int]] = defaultdict(list)
    for addr, node in nodes_patch.items():
        if not is_unnamed(node.name):
            patch_by_name[node.name].append(addr)

    pairs: list[tuple[int, int, str, float]] = []
    matched_old: set[int] = set()
    matched_patch: set[int] = set()

    for addr, node in nodes_old.items():
        if is_unnamed(node.name):
            continue
        # Excludes patched addresses already claimed by an EARLIER old-side
        # function with the same name -- without this, two different
        # old-side functions sharing a name (duplicate/overloaded/templated
        # names demangling identically -- the same phenomenon already
        # handled below for candidates on the patched side) could both
        # independently pick the SAME single patched address, breaking the
        # 1:1 pairing invariant with no detection. Confirmed real gap
        # 2026-08-16. A second duplicate that loses out here falls through
        # (not added to matched_old) to the structural greedy-matching pass
        # below, which DOES already guard against double-assignment.
        candidates = [c for c in patch_by_name.get(node.name, [])
                      if c not in matched_patch]
        if len(candidates) == 1:
            p_addr = candidates[0]
            pairs.append((addr, p_addr, "name", 1.0))
            matched_old.add(addr)
            matched_patch.add(p_addr)
        elif len(candidates) > 1:
            # Duplicate name across multiple patched addresses (overloads/
            # templates demangling to the same text) -- disambiguate
            # structurally among just these candidates.
            best = max(candidates, key=lambda p: _structural_score(nodes_old, node, nodes_patch, nodes_patch[p]))
            pairs.append((addr, best, "name+structural-disambig", 0.9))
            matched_old.add(addr)
            matched_patch.add(best)

    remaining_old = [a for a in nodes_old if a not in matched_old and is_unnamed(nodes_old[a].name)]
    remaining_patch = [a for a in nodes_patch if a not in matched_patch and is_unnamed(nodes_patch[a].name)]

    scored = []
    for oa in remaining_old:
        old_node = nodes_old[oa]
        for pa in remaining_patch:
            s = _structural_score(nodes_old, old_node, nodes_patch, nodes_patch[pa])
            if s > _STRUCTURAL_SCORE_FLOOR:
                scored.append((s, oa, pa))
    scored.sort(reverse=True)

    used_old: set[int] = set()
    used_patch: set[int] = set()
    for s, oa, pa in scored:
        if oa in used_old or pa in used_patch:
            continue
        used_old.add(oa)
        used_patch.add(pa)
        pairs.append((oa, pa, "structural", s))

    unmatched_old = [a for a in remaining_old if a not in used_old]
    unmatched_patch = [a for a in remaining_patch if a not in used_patch]
    return pairs, unmatched_old, unmatched_patch


def classify(nodes_old: dict[int, CallNode], nodes_patch: dict[int, CallNode],
             pairs: list[tuple[int, int, str, float]]) -> list[dict]:
    """category: 'unchanged' (identical size+blocks AND identical constant
    operands), 'noise' (matches a known compiler/library-generated identity
    -- WIL telemetry, MSVC adjustor thunks -- so a real hand-written change
    inside one is implausible), or 'candidate' (worth a real `diff`).

    Deliberately does NOT skip on size/block-count alone: a function being
    small doesn't mean a change inside it is insignificant (a single-branch
    bounds-check helper is exactly the shape of function most likely to
    carry a real one-line security fix), and the local LLM call to check is
    cheap. Only skip on an identity we're confident isn't hand-written.

    'unchanged' was previously the one category with a hard guarantee
    (identical size AND block count), but that guarantee has a real gap:
    many x86-64 immediate encodings are fixed-width regardless of value, so
    a changed constant -- a buffer size, a comparison threshold, a bitmask --
    can leave size and block count completely untouched. Real motivating
    example from this session's own crypt32.dll validation:
    `InitCmsRecipientEncodeInfo`'s allocation math changed from `352 * a2` to
    `a2 << 9` (512 * a2) with no structural change at all. A pair that would
    otherwise be 'unchanged' is promoted to 'candidate' (`promoted_by_constants:
    True`) when `CallNode.constant_operands` differs -- see
    `call_graph._extract_constants` for what counts as a tracked constant
    (deliberately excludes address-like/offset-resolved operands, which
    differ across any two builds via relocation regardless of logic
    changes, and small near-universal values like 0/1/2/4/8)."""
    results = []
    for old_addr, patch_addr, method, confidence in pairs:
        old_node = nodes_old[old_addr]
        patch_node = nodes_patch[patch_addr]
        identical = (old_node.size_bytes == patch_node.size_bytes and
                     old_node.basic_block_count == patch_node.basic_block_count)
        constants_changed = set(old_node.constant_operands) != set(patch_node.constant_operands)
        noisy = is_noise_name(old_node.name) or is_noise_name(patch_node.name)
        if identical and constants_changed:
            category = "candidate"
        elif identical:
            category = "unchanged"
        elif noisy:
            category = "noise"
        else:
            category = "candidate"
        entry = {
            "old_address": old_addr, "patched_address": patch_addr,
            "old_name": old_node.name, "patched_name": patch_node.name,
            "match_method": method, "match_confidence": round(confidence, 3),
            "old_size": old_node.size_bytes, "patched_size": patch_node.size_bytes,
            "old_bb": old_node.basic_block_count, "patched_bb": patch_node.basic_block_count,
            "category": category,
        }
        if identical and constants_changed:
            entry["promoted_by_constants"] = True
        results.append(entry)
    return results


def find_new_and_removed(
    nodes_old: dict[int, CallNode], nodes_patch: dict[int, CallNode],
    pairs: list[tuple[int, int, str, float]]
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """A named function with NO counterpart on the other side is invisible to
    `auto_pair` by construction -- it only ever matches starting from a name
    or structural candidate that exists on both sides. Real example that
    motivated this (2026-08-07): a patch added `CClfsLogCcb::CheckReservation`
    and `::RecordReservation` as brand-new helpers, called from 7 changed
    functions -- every one of those 7 got diffed, but the new helpers
    themselves, arguably the actual fix, were never looked at directly.

    A second real pattern showed up here specifically (2026-08-11, ntfs.sys
    and http.sys): WIL feature-staging accessors carry their feature's ID in
    the name (`Feature_<id>__private_IsEnabledFallback` etc), so a build that
    just rotates which feature ID is active looks like a same-shaped function
    being removed under one name and added under another -- real churn, but
    not a hand-written code change worth an LLM call or a place in the
    console output. `is_noise_name` (already used to skip LLM calls on
    matched pairs) gets the same treatment here: noise-named new/removed
    functions are split into their own noise_new/noise_removed lists rather
    than being silently excluded -- still counted and still in the JSON
    report, just not sent to the LLM.

    Returns (new, removed, noise_new, noise_removed): named functions present
    only in patched / only in old, split by whether the name matches a known
    boilerplate pattern."""
    matched_old = {p[0] for p in pairs}
    matched_patch = {p[1] for p in pairs}
    new, noise_new = [], []
    for a, n in nodes_patch.items():
        if a in matched_patch or is_unnamed(n.name):
            continue
        entry = {"address": a, "name": n.name, "size": n.size_bytes, "bb": n.basic_block_count}
        (noise_new if is_noise_name(n.name) else new).append(entry)
    removed, noise_removed = [], []
    for a, n in nodes_old.items():
        if a in matched_old or is_unnamed(n.name):
            continue
        entry = {"address": a, "name": n.name, "size": n.size_bytes, "bb": n.basic_block_count}
        (noise_removed if is_noise_name(n.name) else removed).append(entry)
    return new, removed, noise_new, noise_removed


def compute_relatedness(nodes: dict[int, CallNode],
                         items: dict[int, str]) -> dict[int, list[tuple[int, str, str]]]:
    """`items` is an address->name map within ONE side's graph (e.g. every
    candidate's patched_address plus every new function's address, checked
    against the patched call graph). Returns, per address in `items`, the
    other `items` it calls or is called by as (address, name, relation) --
    the address is kept (not just the name) so a caller can look up that
    neighbour's own analysis result, once it has one, instead of just naming
    it (see diff.format_related_note)."""
    related: dict[int, list[tuple[int, str, str]]] = {a: [] for a in items}
    for a in items:
        node = nodes.get(a)
        if not node:
            continue
        for callee in node.callee_addresses:
            if callee in items and callee != a:
                related[a].append((callee, items[callee], "calls"))
                related[callee].append((a, items[a], "called_by"))
    return related


def sort_leaves_first(items_meta: list[dict], related: dict[int, list[tuple[int, str, str]]]) -> list[dict]:
    """Order `new`/`removed` items so a function that calls fewer OTHER items
    in this same set goes first. Processing leaves before their callers
    maximizes how often a later item's related-note can include an
    already-computed summary of its neighbour instead of just a bare name
    (see diff.format_related_note) -- e.g. a WIL `...IsEnabledFallback` leaf
    gets summarized before the `...IsEnabledDeviceUsageNoInline` wrapper that
    calls it."""
    def calls_within_set(addr: int) -> int:
        return sum(1 for _addr, _name, rel in related.get(addr, []) if rel == "calls")
    return sorted(items_meta, key=lambda f: calls_within_set(f["address"]))


def auto_pair_full(old_graph_path: str, patch_graph_path: str) -> dict:
    """Everything `diff --auto` needs in one call: classified pairs, new/removed
    functions, and relatedness (computed separately per side, since `new` only
    exists patched-side and `removed` only exists old-side -- see
    compute_relatedness)."""
    graph_old = CallGraph.load(old_graph_path)
    graph_patch = CallGraph.load(patch_graph_path)
    nodes_old, nodes_patch = graph_old.nodes, graph_patch.nodes

    pairs, _unmatched_old, _unmatched_patch = auto_pair(nodes_old, nodes_patch)
    classified = classify(nodes_old, nodes_patch, pairs)
    new, removed, noise_new, noise_removed = find_new_and_removed(nodes_old, nodes_patch, pairs)

    candidates = [r for r in classified if r["category"] == "candidate"]

    patch_items = {r["patched_address"]: r["patched_name"] for r in candidates}
    patch_items.update({n["address"]: n["name"] for n in new})
    old_items = {r["old_address"]: r["old_name"] for r in candidates}
    old_items.update({r["address"]: r["name"] for r in removed})

    related_patch = compute_relatedness(nodes_patch, patch_items)
    related_old = compute_relatedness(nodes_old, old_items)

    return {
        "classified": classified, "new": new, "removed": removed,
        "noise_new": noise_new, "noise_removed": noise_removed,
        "related_patch": related_patch, "related_old": related_old,
    }
