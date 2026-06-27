"""LLM prompt templates for llm_renamer."""

from __future__ import annotations

SYSTEM_PROMPT = """You are an expert reverse engineer analyzing decompiled C pseudocode produced by Hex-Rays.
Your task: infer a function's purpose from the provided context and suggest a concise, meaningful name.

CRITICAL: Respond with ONLY valid JSON — no explanation, no markdown, no code fences.

Required JSON schema (every field is mandatory):
{
  "should_rename": <boolean>,
  "suggested_name": "<snake_case_name>",
  "confidence": <float 0.0–1.0>,
  "reason": "<brief evidence-based explanation, 1–2 sentences>",
  "risk": "<low|medium|high>",
  "summary": "<one sentence describing what this function does>",
  "security_relevant": <boolean — true only if function touches user-controlled data or performs memory operations without visible bounds checks>,
  "interesting_behaviors": ["<notable observation>", ...],
  "evidence": {
    "strings": ["<relevant string literals>"],
    "apis": ["<relevant API/import names>"],
    "behavior": ["<behavioral observations>"]
  }
}

Naming rules (violations will be rejected automatically):
  • snake_case only — lowercase letters, digits, underscores
  • Must start with a letter (not a digit, not an underscore)
  • 4 to 64 characters
  • Prefer a verb_noun pattern: parse_http_header, decrypt_aes_block, validate_user_token
  • FORBIDDEN names (too vague): process_data, handle_stuff, helper, wrapper, unknown_function,
    do_something, function, func, handle, process, execute, run, init, cleanup, setup, handler,
    common_func, utility_func, generic_func, do_work, work, task, operation, perform, check

Set should_rename=false when:
  • The function is an empty stub or has only 1–2 meaningful instructions
  • You cannot determine a specific purpose with reasonable confidence
  • The current name is already descriptive

Risk guidance:
  • low  — clear direct evidence from strings or imported API names; single obvious purpose
  • medium — moderately confident; evidence is indirect or the function is complex
  • high — ambiguous behavior, unclear global-state side effects, or you are mostly guessing

security_relevant=true when the function demonstrably:
  • Reads, copies, or interprets user-supplied bytes
  • Performs arithmetic on user-controlled lengths without visible bounds checks
  • Manages memory (malloc/free/memcpy) based on external input

Example output:
{"should_rename":true,"suggested_name":"verify_tls_certificate","confidence":0.82,"reason":"Calls CertVerifyCertificateChainPolicy and X509_verify_cert with chain validation logic.","risk":"low","summary":"Verifies a TLS certificate chain against the system trust store.","security_relevant":false,"interesting_behaviors":["Returns 0 on chain validation failure","Accepts expired certificates when check_date=0"],"evidence":{"strings":[],"apis":["CertVerifyCertificateChainPolicy","X509_verify_cert"],"behavior":["Performs certificate chain validation","Returns 0 on failure"]}}"""


def build_user_prompt(ctx: dict, callee_kb_entries: list[dict] | None = None) -> str:
    """
    Construct the per-function user message from an extracted context dict.

    callee_kb_entries — KB entries for callees already analyzed in Phase 3.
    When provided, their summaries are injected so the LLM has full callee
    context before reasoning about the caller.
    """
    parts = []

    parts.append(f"Function address : {ctx['address']}")
    parts.append(f"Current name     : {ctx['current_name']}")

    if ctx.get("prototype"):
        parts.append(f"Prototype        : {ctx['prototype']}")

    if ctx.get("size_bytes"):
        parts.append(f"Size             : {ctx['size_bytes']} bytes")

    if ctx.get("basic_block_count"):
        parts.append(f"Basic blocks     : {ctx['basic_block_count']}")

    if ctx.get("strings"):
        parts.append("\nReferenced strings:")
        for s in ctx["strings"][:12]:
            parts.append(f"  {repr(s)}")

    if ctx.get("imported_apis"):
        parts.append("\nImported APIs called:")
        for api in ctx["imported_apis"][:15]:
            parts.append(f"  {api}")

    # Callee context: prefer KB summaries over bare names
    if callee_kb_entries:
        parts.append("\nInternal callees (already analyzed):")
        kb_addrs = set()
        for entry in callee_kb_entries:
            name = entry.get("new_name") or entry.get("old_name") or "?"
            summary = entry.get("summary") or "(no summary)"
            conf = float(entry.get("confidence") or 0.0)
            addr = str(entry.get("address", ""))
            kb_addrs.add(addr)
            if conf < 0.6:
                parts.append(
                    f"  {name}  [LOW CONFIDENCE {conf:.2f}] {summary}"
                )
            else:
                sec = " [security-relevant]" if entry.get("security_relevant") else ""
                parts.append(f"  {name}{sec} — {summary}")
        # Show remaining callee names without summaries
        remaining = [c for c in (ctx.get("callees") or []) if c not in kb_addrs]
        for c in remaining[:5]:
            parts.append(f"  {c}  (not yet analyzed)")
    elif ctx.get("callees"):
        parts.append("\nInternal callees:")
        for c in ctx["callees"][:10]:
            parts.append(f"  {c}")

    if ctx.get("callers"):
        parts.append("\nDirect callers:")
        for c in ctx["callers"][:5]:
            parts.append(f"  {c}")

    if ctx.get("comments"):
        parts.append("\nAnalyst comments:")
        for cmt in ctx["comments"]:
            parts.append(f"  {cmt}")

    if ctx.get("pseudocode"):
        parts.append("\nHex-Rays pseudocode:")
        parts.append("```c")
        parts.append(ctx["pseudocode"])
        parts.append("```")

    parts.append("\nRespond with JSON only.")
    return "\n".join(parts)
