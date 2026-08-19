"""
Structural body-family detection.

Recognizes when two functions' decompiled bodies are identical except for
embedded numeric literals and auto-generated address-based identifiers -- the
shape of a syscall-dispatch cluster, a duplicated obfuscation-primitive
family, or a set of near-identical thunks. Feeds two things: a deterministic
"you are one of a family" signal injected into the analyze prompt
(prompts._render_family_signal), and a stronger-than-name-suffix grouping key
for `ask` search dedup (ask.py's semantic_query).

Real, measured motivation: a ~40-function syscall-dispatch cluster on a real
malware sample, bodies identical except for one embedded syscall number,
caused a 126-conflict naming-collision repair storm across 5 rounds of
refiner.repair_naming_conflicts() that never converged (2026-08). The only
fix that shipped then was a narrow, syscall-number-specific post-processor
(validator._inject_syscall_number) -- this module is the general fix.

Pure text normalization over pseudocode idapro_client.py already decompiled
for the analyze prompt -- this module never decompiles anything itself and
has no ida_hexrays import, so it cannot regress call_graph.py's documented
"map --build is instant, no LLM, no decompile" guarantee.
"""

from __future__ import annotations

import hashlib
import re

_ADDR_IDENT_RE = re.compile(
    r"\b(?:sub|loc|locret|off|byte|word|dword|qword|unk)_[0-9A-Fa-f]+\b"
)
_HEX_LIT_RE = re.compile(r"\b0[xX][0-9A-Fa-f]+\b")
_DEC_LIT_RE = re.compile(r"(?<![\w.])\d+(?:[uUlL]{0,3})\b")
_COMMENT_RE = re.compile(r"//.*$", re.MULTILINE)
# Matched FIRST so string/char literal CONTENTS are copied through verbatim,
# never touched by the substitutions above -- two bodies differing only in an
# embedded literal (a C2 IP, a port, a magic string) must stay
# distinguishable, or exactly the samples this module is meant to help with
# become the ones it wrongly merges. Confirmed real risk, not hypothetical:
# "192.168.1.1" and "192.168.1.2" would otherwise both normalize to the same
# "NUM.NUM.NUM.NUM" placeholder.
_STR_OR_CHAR_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')

# Same threshold/rationale as refiner._is_trivial_body: below this many real
# lines, a shared hash is coincidence (two unrelated trivial one-liners) far
# more often than a real structural family, and the signal becomes noise.
MIN_REAL_LINES = 8


def _real_lines(text: str) -> list[str]:
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln and ln not in ("{", "}")]


def is_hashable(normalized: str) -> bool:
    """True if `normalized` (already run through normalize_pseudocode) has
    enough real body content for a shared hash to mean something."""
    return len(_real_lines(normalized)) >= MIN_REAL_LINES


def _normalize_span(span: str) -> str:
    span = _ADDR_IDENT_RE.sub("ADDR", span)
    span = _HEX_LIT_RE.sub("NUM", span)
    span = _DEC_LIT_RE.sub("NUM", span)
    return span


def normalize_pseudocode(text: str) -> str:
    """Strip the signature, comments, and every numeric/address-identifier
    literal -- but never touch string/char literal contents, real callee
    names, or real variable names (Hex-Rays already names locals consistently
    by position/type for identical bodies; a real, already-meaningful callee
    name is kept so genuinely-different forwarding thunks that call different
    real targets are never wrongly collapsed into one family). See module
    docstring for the real-code motivation."""
    if not text:
        return ""
    text = _COMMENT_RE.sub("", text)
    lines = text.splitlines()
    body_start = 0
    for i, ln in enumerate(lines):
        if "{" in ln:
            body_start = i + 1
            break
    body = "\n".join(lines[body_start:])

    out: list[str] = []
    last = 0
    for m in _STR_OR_CHAR_RE.finditer(body):
        out.append(_normalize_span(body[last:m.start()]))
        out.append(m.group(0))  # literal preserved verbatim
        last = m.end()
    out.append(_normalize_span(body[last:]))
    return "".join(out)


def body_hash(normalized: str) -> str:
    """16 hex chars (64 bits) of sha256 of already-normalized text --
    collision risk at a few thousand functions per binary is negligible (the
    birthday bound needs on the order of 2**32 items)."""
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16]


def render_family_lines(members: list[dict], total: int) -> list[str]:
    """Shared prompt text for "you are one of a structural family" -- called
    from both prompts.build_user_prompt (the initial analyze pass) and
    refiner._build_prompt (refine/repair), so the two prompt builders never
    drift into two different wordings of the same fact. Returns [] (render
    nothing) when `members` is empty -- most functions have no structural
    siblings at all."""
    if not members:
        return []
    lines = [
        f"\nStructural family (deterministic, precomputed): this function's "
        f"body is structurally identical to {total} other function(s) in "
        f"this binary -- same code shape, differing only in an embedded "
        f"numeric literal (e.g. a syscall/opcode number) and/or a referenced "
        f"address. This is a known, expected pattern (a dispatch table, a "
        f"family of thunks), not evidence of anything unusual. A shared or "
        f"parameterized name reflecting the pattern (naming what THIS "
        f"member's own literal specifically is, if you can identify it) is "
        f"fine -- do not invent a distinct, unsupported behavior just to "
        f"make this member's name look unique."
    ]
    for m in members:
        name = m.get("new_name") or m.get("old_name") or m.get("address", "?")
        summary = m.get("summary") or "(not yet analyzed)"
        lines.append(f"  {name} — {summary}")
    return lines
