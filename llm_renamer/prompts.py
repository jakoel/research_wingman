"""LLM prompt templates for llm_renamer."""

from __future__ import annotations

import os
import re
import struct

from . import family

# Every system prompt in the whole tool (analyze x2, refine, repair, diff x4)
# lives as a plain-text .md file here, not as a Python string literal --
# auditing or tuning a prompt is then "open a file", not "find the right
# constant across three modules". Sibling to llm_renamer/, not nested inside
# it, so it reads as content rather than code.
_PROMPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts"
)


def load_prompt(name: str) -> str:
    """Read a system prompt from prompts/<name> verbatim (no templating --
    the file's entire content IS the prompt sent to the LLM).

    Hard-fails on a missing file rather than falling back to anything --
    silently running with a stale or wrong prompt is worse than the tool
    refusing to start.
    """
    path = os.path.join(_PROMPTS_DIR, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"prompt file not found: {path}\n"
            f"       Every system prompt lives in {_PROMPTS_DIR} -- "
            f"see README.md."
        ) from None

# --- Constant decoding: annotate developer-authored magic numbers inline ----
#
# Decompiled pseudocode is full of magic constants that are precise,
# intentional labels the decompiler renders as opaque numbers: 4-byte pool
# tags (subsystem/purpose of an allocation) and NTSTATUS codes (exactly what a
# function validates or returns). Annotating them deterministically before the
# LLM sees them turns guesses into facts at zero LLM cost and no hallucination
# risk — the model was observed decoding these inconsistently (and sometimes
# wrongly) when left to do it itself.

# Common NTSTATUS values seen in kernel code. Not exhaustive on purpose —
# unknown codes in the CLFS facility range are handled generically below.
_NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC000001C: "STATUS_INVALID_DEVICE_STATE",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
    0xC0000095: "STATUS_INTEGER_OVERFLOW",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000225: "STATUS_NOT_FOUND",
}


def _decode_status(v: int) -> str | None:
    v &= 0xFFFFFFFF
    if v in _NTSTATUS:
        return _NTSTATUS[v]
    # Unknown but well-formed NTSTATUS with a non-zero custom facility (the
    # driver's own status codes, e.g. facility 0x1A on this CLFS sample).
    # Reported factually as severity + facility + code rather than a guessed
    # symbolic name -- still tells the model "this is a structured status,
    # not a magic number", and a facility that recurs across the binary is a
    # strong signal these are the component's own error space. Standard
    # facility-0 codes come from the table above; requiring facility != 0 and
    # code != 0 here keeps round bitmasks (0xC0000000, 0xFFFFFFFE) out.
    sev = v >> 30            # 0 success, 1 info, 2 warning, 3 error
    facility = (v >> 16) & 0xFFF
    code = v & 0xFFFF
    # Real facilities are small (standard 0-51; driver-custom ones like 0x1A,
    # 0x22 stay well under 0x100). A facility field of 0xFFF etc. is mask bits,
    # not a status -- e.g. 0xFFFFFFFE (-2) must not be decoded.
    if sev in (2, 3) and 0 < facility < 0x100 and code != 0:
        kind = "error" if sev == 3 else "warning"
        return f"NTSTATUS {kind} (facility 0x{facility:X}, code 0x{code:04X})"
    return None


def _decode_pool_tag(v: int) -> str | None:
    """A 4-byte value whose bytes are all printable and mostly alphanumeric is
    almost certainly a pool tag; render it as its little-endian ASCII."""
    b = struct.pack("<I", v & 0xFFFFFFFF)
    if all(0x20 <= c < 0x7F for c in b):
        s = b.decode("ascii")
        if sum(ch.isalnum() for ch in s) >= 3:
            return s
    return None


# 0x + exactly 8 hex digits (not part of a longer hex literal, so 64-bit
# constants and addresses aren't misread as dword tags/status), plus any
# C integer suffix (u/l/i64/ull/...) so the annotation lands after the whole
# literal, not before the suffix.
_HEX32_RE = re.compile(r"0x([0-9A-Fa-f]{8})(?![0-9A-Fa-f])(?:u|l|i|64)*",
                       re.IGNORECASE)
# A large decimal constant with an LL suffix — how the decompiler renders
# 32-bit status codes it didn't fold to hex (e.g. 3221225485LL).
_DECLL_RE = re.compile(r"\b(\d{7,})LL\b")


def annotate_constants(code: str) -> str:
    """Append `/* ... */` hints to pool-tag and NTSTATUS magic constants."""
    if not code:
        return code

    def _hex(m: "re.Match") -> str:
        v = int(m.group(1), 16)
        tag = _decode_pool_tag(v)          # printable bytes win — it's a tag
        if tag:
            return f"{m.group(0)} /* '{tag}' */"
        status = _decode_status(v)
        if status:
            return f"{m.group(0)} /* {status} */"
        return m.group(0)

    def _decll(m: "re.Match") -> str:
        v = int(m.group(1))
        if v < 0x80000000 or v > 0xFFFFFFFF:   # only 32-bit high-bit-set range
            return m.group(0)
        status = _decode_status(v)
        return f"{m.group(0)} /* {status} */" if status else m.group(0)

    return _DECLL_RE.sub(_decll, _HEX32_RE.sub(_hex, code))


# Body tokens eligible for rewrite to a callee's proposed name: IDA
# auto-generated names and our own uncertain `maybe_` hedge. NOT real applied
# names (e.g. collision-suffixed `foo_2`), which already read well and whose
# suffix carries disambiguation the base new_name lacks. `maybe_` mirrors
# analysis.uncertain_prefix; keep in sync if that config default ever changes.
_REPLACEABLE_PREFIXES = (
    "sub_", "nullsub_", "j_", "locret_", "loc_", "unknown_libname", "maybe_",
)


def _live_name_for(entry: dict, addr_live_names: dict[str, str] | None) -> str:
    """The name the database shows for this KB row RIGHT NOW, looked up by
    address (the single live-name authority, ARCHITECTURE §3a). Empty string
    when no address map is available for this neighbour."""
    if not addr_live_names:
        return ""
    addr = str(entry.get("address") or "").strip()
    if not addr:
        return ""
    try:
        canonical = f"0x{int(addr, 16):X}"
    except ValueError:
        return ""
    return (addr_live_names.get(canonical) or addr_live_names.get(addr) or "").strip()


def name_substitutions(
    kb_entries: list[dict] | None,
    addr_live_names: dict[str, str] | None = None,
) -> dict[str, str]:
    """{current_body_token: proposed_name} for neighbours whose live name is
    still a placeholder (`sub_...`, `maybe_...`, see `_REPLACEABLE_PREFIXES`).

    This is the single definition of "which neighbours get shown under their
    proposed name rather than their live one" -- used BOTH to rewrite the
    pseudocode body (`substitute_callee_names`) and to label the neighbour
    listing (`_render_kb_neighbours`). Deriving both from one map is what
    keeps a summary's heading identical to the token it describes in the
    body; computing them separately is exactly how they drifted before (a
    callee applied as `wrapper_identity_10` was listed under its
    pre-uniquification base `wrapper_identity`, which appears nowhere in the
    body -- measured stranding a callee summary in 64 of 355 functions).
    """
    subs: dict[str, str] = {}
    for e in kb_entries or []:
        new = (e.get("new_name") or "").strip()
        if not new:
            continue
        live = _live_name_for(e, addr_live_names)
        # Prefer the live name (authority); fall back to KB shadow fields only
        # when this neighbour isn't in the address map at all.
        candidates = [live] if live else [e.get("old_name"), e.get("applied_name")]
        for old in candidates:
            old = (old or "").strip()
            if old and old != new and old.startswith(_REPLACEABLE_PREFIXES):
                subs[old] = new
    return subs


def display_name_for(
    entry: dict,
    addr_live_names: dict[str, str] | None,
    subs: dict[str, str],
) -> str:
    """The name a neighbour must be LISTED under so its summary matches the
    identifier the reader actually sees in the body. Derived from the same
    `subs` map that rewrites the body, so the two cannot disagree."""
    live = _live_name_for(entry, addr_live_names)
    if live:
        return subs.get(live, live)
    for shadow in (entry.get("old_name"), entry.get("applied_name")):
        shadow = (shadow or "").strip()
        if shadow and shadow in subs:
            return subs[shadow]
    return (entry.get("new_name") or entry.get("old_name") or "?").strip()


def substitute_callee_names(
    pseudocode: str,
    callee_kb_entries: list[dict] | None,
    callee_addr_names: dict[str, str] | None = None,
) -> str:
    """Rewrite the decompiled body so analyzed callees appear under their
    proposed new name instead of the raw name IDA currently shows.

    analyze() never renames the database (invariant 9), so the body always shows
    callees' *current* DB names (`sub_1C0006E80`, or a stale `maybe_check_2`)
    while their summaries are injected keyed by the proposed `new_name`. Left
    alone, the model cannot map a summary to the call it describes — measured at
    ~85% of visible callee summaries stranded on a fresh bottom-up run. Swapping
    the names inline closes that gap and lets the reader (and the LLM) see a call
    like `compute_crc_checksum_loop(...)` instead of `sub_1C0006E80(...)`.

    The token actually in the body is the callee's *current* name. The single
    authority for that is `callee_addr_names` ({hex-addr: live IDA name}, from the
    extractor -- see ARCHITECTURE §3a); we use it when present and fall back to the
    KB shadow fields `old_name`/`applied_name` only when it isn't (e.g. a callee
    reached indirectly, not in the direct-callee map). We map the body token to
    `new_name`. Whole-word only, approved callees only (a rejected callee has no
    better name, so its body token is left as-is). A token that isn't in the body
    is a harmless no-op.

    Only *raw or placeholder* body tokens are rewritten (see `_REPLACEABLE_PREFIXES`):
    `sub_...`, `unknown_libname...`, a `maybe_...` hedge, etc. An already-applied
    descriptive name is left alone — crucially, a collision-disambiguated name like
    `get_control_record_4` (whose KB new_name is the base `get_control_record`) must
    NOT be rewritten, or three distinct callees would collapse to one name in the body.
    """
    if not pseudocode or not callee_kb_entries:
        return pseudocode
    subs = name_substitutions(callee_kb_entries, callee_addr_names)
    if not subs:
        return pseudocode
    # Longer tokens first so a name that is a prefix of another is handled
    # deterministically (the \b guards already prevent partial-token matches).
    for old in sorted(subs, key=len, reverse=True):
        pseudocode = re.sub(r"\b" + re.escape(old) + r"\b", subs[old], pseudocode)
    return pseudocode


# A demangled C++ qualified method name, e.g. "CClfsLogFcbPhysical::ReadLog"
# or "Ns::Class::Method". Windows components built with WPP software tracing
# embed each function's own fully-qualified name as a literal string passed to
# its entry/exit trace calls — near-ground-truth naming signal sitting in the
# binary for free. Deliberately strict: matching a genuine `Class::Method` and
# occasionally missing an exotic form is fine; a false positive that hijacks
# the name off some unrelated string is not.
_METHOD_NAME_RE = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+")


def method_name_strings(strings: list[str] | None) -> list[str]:
    """
    Return the subset of `strings` that are C++ qualified method names.

    One of these referenced by a function is very likely its own name (the
    WPP trace string). Kept order-preserving and de-duplicated. Not a hard
    naming decision on its own — a function can reference several method-name
    strings (its own plus ones it logs on behalf of callees), and the same
    string is shared by overload/thunk variants — so this feeds the prompt as
    a strong hint the LLM reconciles against the code, rather than renaming
    blindly.
    """
    out: list[str] = []
    seen: set[str] = set()
    for s in strings or []:
        m = _METHOD_NAME_RE.fullmatch(s.strip())
        if m and s.strip() not in seen:
            seen.add(s.strip())
            out.append(s.strip())
    return out

_SYSTEM_PROMPT_VULN_RESEARCH = load_prompt("analyze_vuln_research.md")


# Malware-triage variant. Same JSON schema and structural/naming rules as the
# vuln-research prompt above (validator.py parses one schema regardless of
# profile) -- only the analytical framing changes: what counts as
# security_relevant, what risk actually costs, and what interesting_behaviors
# should be watching for. Written after a real miss: analyzing a MIPS botnet
# sample, the vuln-research prompt was handed a function referencing a
# hardcoded C2 IP right next to an XOR-obfuscation call and still named it
# "initialize_system_pool_and_dispatch_table" -- technically not wrong (it
# does allocate pool blocks and populate a dispatch table), but it buried the
# one fact that mattered because nothing in that prompt told the model a
# bare IP literal is itself the finding. Memory-safety framing
# (user-controlled length, missing bounds check) has no purchase on a
# statically-linked bot binary with no external caller input in the usual
# sense -- the questions worth asking are different, not just additively so.
_SYSTEM_PROMPT_MALWARE = load_prompt("analyze_malware.md")


# Profile -> system prompt. "vuln_research" is the original prompt (unchanged
# text) the tool's ~91% accuracy figure in sauce.md was measured against, so
# it stays the default for anything that doesn't opt into "malware" via
# config["analysis"]["profile"] or `analyze --profile`.
SYSTEM_PROMPTS = {
    "vuln_research": _SYSTEM_PROMPT_VULN_RESEARCH,
    "malware": _SYSTEM_PROMPT_MALWARE,
}


def get_system_prompt(profile: str | None) -> str:
    """Resolve a config['analysis']['profile'] value to its system prompt.
    Unknown or missing profile falls back to vuln_research."""
    return SYSTEM_PROMPTS.get(profile or "", _SYSTEM_PROMPT_VULN_RESEARCH)


def _render_kb_neighbours(
    parts: list[str], header: str, kb_entries: list[dict] | None,
    bare_names: list[str] | None, bare_limit: int,
    addr_live_names: dict[str, str] | None = None,
    low_conf_threshold: float = 0.65,
) -> None:
    """
    Render a neighbour section (callees or callers): KB summaries first for
    whichever are already analyzed, then any remaining bare names still
    unanalyzed. Shared so callees and callers get identical treatment —
    they used to diverge (callees got summaries, callers got bare names
    only), which was itself a real gap in how much context the LLM had.

    Each neighbour is listed under `display_name_for` — the name it actually
    appears under in the pseudocode body, not its raw KB `new_name` (see
    `name_substitutions`).

    `kb_entries` (every already-analyzed neighbour) is shown in FULL, never
    capped -- direct children only, never grandchildren (`callees_of`/
    `callers_of` in call_graph.py are one-hop edge lookups; there is no
    transitive walk anywhere), and every direct child gets both its name and
    its real summary, by explicit design choice (2026-08-16) over an earlier
    cap-at-5 that was tried and reverted -- capping traded real per-function
    evidence for prompt-size economy, which is the wrong trade for a
    dispatcher/orchestrator with dozens of real callees (worst case seen so
    far: 64). `kb` still orders security-relevant, higher-confidence rows
    first (see KnowledgeBase._by_addresses), so even an unusually long
    listing reads most-important-first.

    Only `bare_names` (neighbours with NO KB entry yet -- genuinely
    unanalyzed) is capped, at `bare_limit`: those carry no real content
    beyond "not yet analyzed", so a long tail of them is pure filler, unlike
    a real summary.
    """
    kb_entries = kb_entries or []
    bare_names = bare_names or []
    if not kb_entries and not bare_names:
        return

    subs = name_substitutions(kb_entries, addr_live_names)

    kb_names: set[str] = set()
    for entry in kb_entries:
        name = display_name_for(entry, addr_live_names, subs)
        # ctx["callees"]/ctx["callers"] hold whatever name IDA currently shows
        # (old or already-applied), never an address — so dedup against every
        # name this row could surface under, not the address.
        kb_names.add(name)
        kb_names.add(str(entry.get("old_name") or ""))
        kb_names.add(str(entry.get("new_name") or ""))
        # The body may still show a prior applied name (e.g. an intermediate
        # `maybe_...`); dedup against it too so substitute_callee_names swapping
        # it to new_name doesn't leave it wrongly listed as "not yet analyzed".
        kb_names.add(str(entry.get("applied_name") or ""))

    parts.append(header)
    for entry in kb_entries:
        name = display_name_for(entry, addr_live_names, subs)
        summary = entry.get("summary") or "(no summary)"
        conf = float(entry.get("confidence") or 0.0)
        if conf < low_conf_threshold:
            parts.append(f"  {name}  [LOW CONFIDENCE {conf:.2f}] {summary}")
        else:
            sec = " [security-relevant]" if entry.get("security_relevant") else ""
            parts.append(f"  {name}{sec} — {summary}")

    remaining = [n for n in bare_names if n not in kb_names]
    for n in remaining[:bare_limit]:
        parts.append(f"  {n}  (not yet analyzed)")


def _render_family_signal(parts: list[str], ctx: dict) -> None:
    """Deterministic "you are not unique" signal for a structurally-identical
    body family (see family.py) -- the shared-bucket framing already
    established for wrapper_*/_is_specific_name (refiner.py) extended to any
    non-trivial body that only differs from siblings by an embedded literal
    (e.g. a syscall/opcode number) or an auto-generated address. Real
    motivation: a ~40-function syscall-dispatch cluster differing only by
    syscall number caused a 126-conflict naming-collision repair storm that
    never converged, because nothing ever told the model it wasn't looking
    at something unique. Only emits anything when family_members is
    non-empty -- most functions have no structural siblings at all."""
    members = ctx.get("family_members") or []
    total = ctx.get("family_size") or len(members)
    parts.extend(family.render_family_lines(members, total))


def _render_graph_signals(parts: list[str], ctx: dict, code_referrers_limit: int = 5) -> None:
    """Append the deterministic call-graph signal section (sinks it calls,
    real ctree-traced parameter-to-sink taint, input-reachability, caller
    count, and indirect/vtable reachability the direct call graph can't see)
    when any are present. See the call site in `build_user_prompt` for why
    these are injected rather than left to the model to re-derive."""
    sinks = list(dict.fromkeys(ctx.get("dangerous_sink_calls") or []))
    input_reachable = bool(ctx.get("input_reachable"))
    caller_count = ctx.get("caller_count")
    indirectly_ref = bool(ctx.get("indirectly_referenced"))
    code_referrers = list(dict.fromkeys(ctx.get("indirect_code_referrers") or []))
    tainted_sinks = ctx.get("tainted_sink_calls") or []

    lines: list[str] = []
    if sinks:
        lines.append(
            "  Calls memory/allocation primitive(s): " + ", ".join(sinks)
            + " — verify each size/length/offset argument is validated here "
              "before the call, not assumed valid."
        )
    # Real dataflow (ctree-traced), not the graph-topology-only sink listing
    # above: this specific call's argument(s) trace back to the function's
    # OWN input parameter, not a local/constant -- a materially stronger
    # claim than "calls a dangerous function somewhere in this function."
    for finding in tainted_sinks:
        sink = finding.get("sink", "")
        args = finding.get("tainted_args") or []
        if not sink or not args:
            continue
        arg_word = "argument" if len(args) == 1 else "arguments"
        arg_list = ", ".join(f"#{n}" for n in args)
        lines.append(
            f"  {sink}'s {arg_word} {arg_list} traced (via decompiler dataflow, "
            f"not a guess) to this function's own input parameter — treat as "
            f"attacker-influenced unless this function itself validates it "
            f"before the call."
        )
    if input_reachable:
        lines.append(
            "  Reachable from an external input source (network/file read) via "
            "the call graph — treat its inputs as potentially attacker-influenced."
        )

    # Caller count, and whether the function is reached indirectly (vtable slot /
    # registered callback / dispatch-table entry) which the direct call graph
    # cannot see. The indirect fact rewrites the caller_count==0 story: without
    # it the model can't tell a real entry point from a vtable slot with no
    # direct callers, and most caller_count==0 functions in a C++ driver are the
    # latter. `indirect_handled` avoids repeating the fact twice.
    n = None
    if caller_count is not None:
        try:
            n = int(caller_count)
        except (TypeError, ValueError):
            n = None
    indirect_handled = False
    if n == 0:
        if indirectly_ref:
            lines.append(
                "  No direct callers — invoked indirectly (a vtable slot, "
                "registered callback, or dispatch-table entry); the call graph "
                "does not track these, so its role is defined by the interface "
                "it implements rather than by a caller."
            )
        else:
            lines.append(
                "  No callers and not referenced as data — a top-level entry "
                "point or unreferenced code."
            )
        indirect_handled = True
    elif n is not None:
        role = " (few — likely a distinct code path, not shared utility)" \
            if n <= 3 else (
                " (many — likely shared utility/glue)" if n >= 20 else "")
        lines.append(f"  Called from {n} direct call site(s){role}.")

    if indirectly_ref and not indirect_handled:
        lines.append(
            "  Also referenced indirectly (vtable/callback/dispatch table), so "
            "it may be invoked through a pointer beyond the direct call site(s) above."
        )
    if code_referrers:
        lines.append(
            "  Its address is taken in the code of: "
            + ", ".join(code_referrers[:code_referrers_limit])
            + " — likely registered there as a callback/handler."
        )

    if lines:
        parts.append("\nCall-graph signals (deterministic, precomputed):")
        parts.extend(lines)


def build_user_prompt(
    ctx: dict,
    callee_kb_entries: list[dict] | None = None,
    caller_kb_entries: list[dict] | None = None,
    config: dict | None = None,
) -> str:
    """
    Construct the per-function user message from an extracted context dict.

    callee_kb_entries / caller_kb_entries — KB entries for callees/callers
    already analyzed. When provided, their summaries are injected so the LLM
    reasons from real context instead of bare names it knows nothing about.

    config — supplies the prompt-content caps below (analysis.max_*_shown in
    config.json/config.py's _TUNING_DEFAULTS); omitted or missing keys fall
    back to the same defaults those caps have always had.
    """
    analysis_cfg = (config or {}).get("analysis", {})
    strings_limit = int(analysis_cfg.get("max_referenced_strings_shown", 12))
    apis_limit = int(analysis_cfg.get("max_imported_apis_shown", 15))
    code_referrers_limit = int(analysis_cfg.get("max_code_referrers_shown", 5))
    # Reuses confidence_threshold itself (not a second, independent number)
    # for the neighbour "[LOW CONFIDENCE]" flag -- confirmed real gap
    # 2026-08-16: KnowledgeBase._by_addresses has no status filter, so a
    # REJECTED neighbour (confidence below confidence_threshold, rejected on
    # its OWN analysis) is still eligible for injection here. A bare
    # independent 0.6 left a window [0.6, confidence_threshold) where a
    # rejected neighbour's summary showed up unflagged, looking as
    # trustworthy as an approved one. Deriving from the same config key
    # closes that gap and can't drift out of sync with it again.
    low_conf_threshold = float(analysis_cfg.get("confidence_threshold", 0.65))
    # Every already-analyzed direct child/caller gets shown, unconditionally
    # (see _render_kb_neighbours) -- this only bounds the tail of neighbours
    # with NO KB entry yet, which carry no content beyond "not yet analyzed".
    unanalyzed_limit = int(analysis_cfg.get("max_unanalyzed_neighbours_shown", 5))

    parts = []

    # Deliberately NOT injected: function address (an opaque hex number with no
    # naming signal), byte size, and basic-block count -- the last two are
    # redundant with the pseudocode the model can already see, and byte size
    # carries no semantic meaning. (basic_block_count is still used in
    # scorer.py, a different consumer; only the prompt drops it.)
    parts.append(f"Current name     : {ctx['current_name']}")

    if ctx.get("prototype"):
        parts.append(f"Prototype        : {ctx['prototype']}")

    # IDA's own typed signature, when it has one richer than the decompiler's
    # first-line guess (library-recognised functions, typed imports, analyst
    # types). Named kernel types like PIRP/PFILE_OBJECT/PCUNICODE_STRING say
    # exactly what a function operates on. Skipped when absent or identical to
    # the prototype above.
    type_sig = (ctx.get("type_signature") or "").strip()
    if type_sig and type_sig != (ctx.get("prototype") or "").strip():
        parts.append(f"IDA type         : {type_sig}")

    # Elevate embedded C++ method-name strings (WPP trace names) above the
    # generic string list -- one of these is very likely this function's own
    # name, the strongest signal we have. Exclude them from the generic list
    # below so the same string isn't shown twice.
    all_strings = ctx.get("strings") or []
    method_names = method_name_strings(all_strings)
    if method_names:
        parts.append("\nEmbedded method-name string(s) referenced by this "
                     "function (one is very likely its own name):")
        for s in method_names:
            parts.append(f"  {s}")

    other_strings = [s for s in all_strings if s.strip() not in set(method_names)]
    if other_strings:
        parts.append("\nReferenced strings:")
        for s in other_strings[:strings_limit]:
            parts.append(f"  {repr(s)}")

    if ctx.get("imported_apis"):
        parts.append("\nImported APIs called:")
        for api in ctx["imported_apis"][:apis_limit]:
            parts.append(f"  {api}")

    # Deterministic call-graph signals (computed in Phase 1, not the model's
    # guesses): which memory/allocation primitives this function calls, whether
    # the graph shows it reachable from an external input source, and how many
    # places call it. These are exactly the facts the security_relevant/risk
    # judgement needs -- previously the model had to re-derive them from the
    # pseudocode, and the raw import list that carries the sink calls is capped
    # at 15 in address order, so a sink (memcpy at position 18, say) could fall
    # off the prompt entirely while the graph still had it flagged. Rendered as
    # factual observations, not conclusions, so the model still confirms the
    # guard/validation state against the actual code.
    _render_graph_signals(parts, ctx, code_referrers_limit=code_referrers_limit)
    _render_family_signal(parts, ctx)

    _render_kb_neighbours(
        parts, "\nInternal callees:",
        callee_kb_entries, ctx.get("callees"), bare_limit=unanalyzed_limit,
        addr_live_names=ctx.get("callee_addr_names"),
        low_conf_threshold=low_conf_threshold,
    )
    _render_kb_neighbours(
        parts, "\nDirect callers:",
        caller_kb_entries, ctx.get("callers"), bare_limit=unanalyzed_limit,
        addr_live_names=ctx.get("caller_addr_names"),
        low_conf_threshold=low_conf_threshold,
    )

    if ctx.get("comments"):
        parts.append("\nAnalyst comments:")
        for cmt in ctx["comments"]:
            parts.append(f"  {cmt}")

    if ctx.get("pseudocode"):
        parts.append("\nHex-Rays pseudocode (pool tags and NTSTATUS codes "
                     "annotated inline):")
        parts.append("```c")
        parts.append(annotate_constants(
            substitute_callee_names(ctx["pseudocode"], callee_kb_entries,
                                    ctx.get("callee_addr_names"))))
        parts.append("```")

    parts.append("\nRespond with JSON only.")
    return "\n".join(parts)
