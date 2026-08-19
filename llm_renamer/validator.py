"""
LLM output validation and name sanitization for llm_renamer.

validate_llm_output() is the single entry point.  It returns a ValidationResult
whose .ok flag indicates whether the suggestion should be used, and whose
.sanitized_name holds the final cleaned-up name if .ok is True.
"""

import re

# ---- Name pattern ----------------------------------------------------------

# After sanitization a valid name must match this.
_VALID_RE = re.compile(r"^[a-z][a-z0-9_]{3,63}$")   # 4..64 chars total (first + rest)

_CAMEL_BOUNDARY_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_BOUNDARY_2 = re.compile(r"([a-z\d])([A-Z])")

# 3-5 digit number not immediately preceded by a hex prefix -- excludes
# picking up e.g. "1062" out of "4194 (0x1062)" as a second, spurious
# candidate for what's really one number stated twice.
_SYSCALL_NUM_RE = re.compile(r"(?<!0x)(?<!x)\b(\d{3,5})\b")
_SYSCALL_WORD_RE = re.compile(r"\bsyscall\b", re.IGNORECASE)

# Required JSON fields (rename decision)
_REQUIRED = frozenset({"should_rename", "suggested_name", "confidence", "reason"})

# Built-in vague-name set (merged with config's list at validation time)
_BUILTIN_VAGUE: frozenset[str] = frozenset({
    "process_data", "handle_stuff", "helper", "wrapper",
    "unknown_function", "do_something", "function", "func",
    "handle", "process", "execute", "run", "init", "cleanup",
    "setup", "teardown", "main_func", "common_func",
    "utility_func", "generic_func", "sub_routine", "routine",
    "method", "callback", "handler", "handler_func",
    "do_work", "work", "task", "operation", "perform",
    "check", "get_data", "set_data", "read_data", "write_data",
    "unknown", "unnamed", "noname",
})


# ---- Result type -----------------------------------------------------------

class ValidationResult:
    __slots__ = ("ok", "reason", "sanitized_name")

    def __init__(self, ok: bool, reason: str = "", sanitized_name: str = ""):
        self.ok = ok
        self.reason = reason
        self.sanitized_name = sanitized_name

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        if self.ok:
            return f"ValidationResult(ok=True, name={self.sanitized_name!r})"
        return f"ValidationResult(ok=False, reason={self.reason!r})"


# ---- Sanitization ----------------------------------------------------------

def _to_snake_case(name: str) -> str:
    """Convert an arbitrary identifier to snake_case."""
    name = re.sub(r"[\s\-\.]+", "_", name)
    name = re.sub(r"[^a-zA-Z0-9_]", "", name)
    name = _CAMEL_BOUNDARY_1.sub(r"\1_\2", name)
    name = _CAMEL_BOUNDARY_2.sub(r"\1_\2", name)
    name = name.lower()
    name = re.sub(r"_+", "_", name)
    name = name.strip("_")
    return name


# ---- Policy helpers --------------------------------------------------------

def is_auto_generated_name(name: str, config: dict) -> bool:
    """
    Return True if name matches any of the IDA auto-generated name prefixes
    defined in config["policy"]["auto_generated_prefixes"].
    """
    prefixes: list[str] = config["policy"].get("auto_generated_prefixes", [
        "sub_", "j_", "nullsub_", "locret_", "loc_",
    ])
    return any(name.startswith(p) for p in prefixes)


def is_analysis_candidate(name: str, config: dict) -> bool:
    """True if `name` is worth spending an LLM call on -- a still-unnamed
    `sub_`-style function (config["policy"]["analysis_candidate_prefixes"]).

    Deliberately narrower than is_auto_generated_name: named functions
    (library/symbol/import/analyst) carry ground truth and trivial auto stubs
    (j_/nullsub_/locret_/loc_) carry nothing, so neither is worth analyzing.
    An explicit `-f` target bypasses this filter (see pipeline.build_plan).
    """
    prefixes: list[str] = config["policy"].get("analysis_candidate_prefixes", ["sub_"])
    return any(name.startswith(p) for p in prefixes)


def _inject_syscall_number(name: str, reason: str, behaviors: list) -> str:
    """A name like `update_pool_block_status` or `execute_syscall_and_update_
    pool_status` says nothing that distinguishes it from a dozen structurally
    identical siblings -- and prompting the model to include the actual
    syscall number itself only works ~20% of the time (measured live: 3/22 on
    a real collision cluster). But the number is reliably present in
    `reason`/`interesting_behaviors` even on the other ~80% -- checked live,
    every case had it in the prose even when the name stayed generic. So
    splice it in mechanically instead of hoping.

    Gated on the TEXT saying "syscall" (never invents syscall-framing the
    model didn't choose), not on the NAME already saying it -- names like
    `update_pool_block_status` describe the same syscall-wrapper shape from
    the pool side instead, and would otherwise never get disambiguated even
    though the reason text states the number just as reliably. Never guesses
    a number the model's own text didn't state, and on a tie between equally-
    mentioned candidates, leaves the name alone rather than pick the wrong one.
    """
    tokens = name.split("_")
    if any(t.isdigit() for t in tokens):
        return name

    text = f"{reason} {' '.join(str(b) for b in (behaviors or []))}"
    if not _SYSCALL_WORD_RE.search(text):
        return name

    counts: dict[str, int] = {}
    for m in _SYSCALL_NUM_RE.finditer(text):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    if not counts:
        return name
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return name
    number = ranked[0][0]

    if "syscall" in tokens:
        idx = tokens.index("syscall")
        tokens.insert(idx + 1, number)
    else:
        tokens.append(number)
    return "_".join(tokens)


# ---- Main validator --------------------------------------------------------

def validate_llm_output(raw: dict, config: dict) -> ValidationResult:
    """
    Validate and sanitize a raw LLM JSON response dict.

    Returns ValidationResult with .ok=True and a cleaned .sanitized_name on
    success, or .ok=False and a human-readable .reason on any failure.
    """
    # 1. Required fields
    missing = _REQUIRED - set(raw.keys())
    if missing:
        return ValidationResult(False, f"Missing required fields: {', '.join(sorted(missing))}")

    # 2. should_rename
    if not isinstance(raw["should_rename"], bool):
        return ValidationResult(False, "should_rename must be a boolean")
    if not raw["should_rename"]:
        return ValidationResult(False, "LLM indicated no rename needed (should_rename=false)")

    # 4. confidence
    try:
        confidence = float(raw["confidence"])
    except (TypeError, ValueError):
        return ValidationResult(False, "confidence must be a number")
    threshold = float(config["analysis"]["confidence_threshold"])
    if confidence < threshold:
        return ValidationResult(False, f"confidence={confidence:.2f} < threshold={threshold:.2f}")

    # 4b. High risk: rejected only below the override confidence -- a
    # low-confidence guess on risky code is exactly the case worth blocking,
    # but a high-confidence one is still stored with risk=high in the KB
    # (still visible to a researcher browsing later), just not auto-rejected.
    risk = str(raw.get("risk", "")).strip().lower()
    high_risk_override = float(config["analysis"].get("high_risk_confidence_override", 0.8))
    if risk == "high" and config["analysis"].get("skip_high_risk", True) \
            and confidence < high_risk_override:
        return ValidationResult(
            False,
            f"risk=high and confidence={confidence:.2f} < "
            f"{high_risk_override:.2f} override threshold",
        )

    # 5. reason non-empty
    # `raw.get(key, "")` only supplies "" when the KEY IS ABSENT -- a
    # syntactically valid `"key": null` response leaves it present with
    # value None, and str(None) == "None" (4 chars) silently sails past
    # both the length-8 reason check and, worse, the name emptiness/length
    # checks below ("none" is a valid-looking 4-char name, not in the vague
    # blacklist). `raw.get(key) or ""` treats null the same as absent.
    # Confirmed real gap 2026-08-16.
    reason = str(raw.get("reason") or "").strip()
    if len(reason) < 8:
        return ValidationResult(False, "reason too short or missing")

    # 6. Name: sanitize → validate
    raw_name = str(raw.get("suggested_name") or "").strip()
    if not raw_name:
        return ValidationResult(False, "suggested_name is empty")

    sanitized = _to_snake_case(raw_name)
    sanitized = _inject_syscall_number(sanitized, reason, raw.get("interesting_behaviors") or [])

    if not sanitized:
        return ValidationResult(False, f"Name {raw_name!r} is empty after sanitization")

    if not sanitized[0].isalpha():
        return ValidationResult(False, f"Sanitized name {sanitized!r} does not start with a letter")

    if not _VALID_RE.match(sanitized):
        return ValidationResult(
            False,
            f"Name {sanitized!r} fails validation (must be 4–64 chars, snake_case, start with letter)",
        )

    max_len = int(config["analysis"]["max_name_length"])
    if len(sanitized) > max_len:
        return ValidationResult(False, f"Name too long ({len(sanitized)} > {max_len}): {sanitized!r}")

    # 7. Vague-name check.
    #
    # EXACT match only, never prefix/substring -- and that is load-bearing, not
    # incidental. The blacklist contains bare `wrapper`, `handler`, `check`,
    # `init`, ... while the analyze prompt REQUIRES `wrapper_<something>` for
    # trivial thunks and legitimately produces `init_error_category_vtable`,
    # `check_buffer_bounds`, etc. A bare `wrapper` says nothing; `wrapper_free_
    # buffer` says exactly what it forwards to. Widening this to a prefix test
    # would reject the naming convention the prompt mandates, so if you ever
    # "tighten" it, exclude these compound forms explicitly.
    vague_from_config: set[str] = set(config["policy"].get("vague_names_blacklist", []))
    vague_all = _BUILTIN_VAGUE | vague_from_config
    if sanitized in vague_all:
        return ValidationResult(False, f"Name is too vague: {sanitized!r}")

    # 8. Low-but-acceptable confidence: flag it in the name itself rather than
    # rejecting outright. Mirrors the "maybe_check_N" convention an analyst
    # had already used by hand elsewhere in this binary.
    uncertain_max = float(config["analysis"].get("uncertain_prefix_max_confidence", 0.7))
    if confidence < uncertain_max:
        prefix = str(config["analysis"].get("uncertain_prefix", "maybe_"))
        candidate = f"{prefix}{sanitized}"
        sanitized = candidate[:max_len].rstrip("_") if len(candidate) > max_len else candidate

    return ValidationResult(True, "", sanitized)
