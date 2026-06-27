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

# Required JSON fields (rename decision)
_REQUIRED = frozenset({"should_rename", "suggested_name", "confidence", "reason", "risk", "evidence"})

# Optional KB fields (present in Phase 3 prompts; extracted but not gating)
_KB_OPTIONAL = frozenset({"summary", "security_relevant", "interesting_behaviors"})

# Valid risk values
_VALID_RISK = frozenset({"low", "medium", "high"})

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

    # 3. risk
    risk = str(raw.get("risk", "")).strip().lower()
    if risk not in _VALID_RISK:
        return ValidationResult(False, f"Invalid risk value: {risk!r} (expected low|medium|high)")
    if config["analysis"].get("skip_high_risk", True) and risk == "high":
        return ValidationResult(False, "risk='high': skipped per policy")

    # 4. confidence
    try:
        confidence = float(raw["confidence"])
    except (TypeError, ValueError):
        return ValidationResult(False, "confidence must be a number")
    threshold = float(config["analysis"]["confidence_threshold"])
    if confidence < threshold:
        return ValidationResult(False, f"confidence={confidence:.2f} < threshold={threshold:.2f}")

    # 5. reason non-empty
    reason = str(raw.get("reason", "")).strip()
    if len(reason) < 8:
        return ValidationResult(False, "reason too short or missing")

    # 6. evidence is a dict
    if not isinstance(raw.get("evidence"), dict):
        return ValidationResult(False, "evidence must be a JSON object")

    # 7. Name: sanitize → validate
    raw_name = str(raw.get("suggested_name", "")).strip()
    if not raw_name:
        return ValidationResult(False, "suggested_name is empty")

    sanitized = _to_snake_case(raw_name)

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

    # 8. Vague-name check
    vague_from_config: set[str] = set(config["policy"].get("vague_names_blacklist", []))
    vague_all = _BUILTIN_VAGUE | vague_from_config
    if sanitized in vague_all:
        return ValidationResult(False, f"Name is too vague: {sanitized!r}")

    return ValidationResult(True, "", sanitized)
