"""
Configuration for llm_renamer.

Two tiers:

  USER      the handful of settings worth editing — shipped in config.json.
  TUNING    everything else (scoring weights, sink lists, name blacklists,
            prompt sizing). Lives in code as defaults. Any of it can still be
            overridden by adding the key to config.json, but it is not there
            by default and most users never touch it.

Paths are NOT configurable here — the Workspace derives every path from the
database location. See workspace.py.
"""

from __future__ import annotations

import os
import json
import copy

# ---------------------------------------------------------------------------
# Tier 1 — settings a user is expected to edit (mirrored in config.json)
# ---------------------------------------------------------------------------

_USER_DEFAULTS = {
    "ollama": {
        "url": "http://localhost:11434",
        "model": "gemma4:26b",
        "embed_model": "nomic-embed-text",
    },
    "analysis": {
        "confidence_threshold": 0.65,
        "skip_high_risk": True,
        # "vuln_research" (default, unchanged prompt) or "malware" -- see
        # prompts.SYSTEM_PROMPTS. Override per-run with `analyze --profile`
        # rather than editing this when switching between target types.
        "profile": "vuln_research",
    },
}

# ---------------------------------------------------------------------------
# Tier 2 — tuning constants. Override in config.json only if you know why.
# ---------------------------------------------------------------------------

_TUNING_DEFAULTS = {
    "ollama": {
        "timeout_seconds": 120,
        "temperature": 0.1,
        "num_ctx": 8192,
    },
    "analysis": {
        "max_name_length": 64,
        "min_pseudocode_lines": 3,
        "max_pseudocode_lines": 200,
        "uncertain_prefix": "maybe_",
        "uncertain_prefix_max_confidence": 0.7,
        "high_risk_confidence_override": 0.8,
        # How much per-function prompt content survives into the LLM call.
        # Every one of these silently drops information past the cap (no
        # truncation marker in the model's view) rather than erroring, so a
        # cap that's too tight for a given binary hides real signal instead
        # of failing loud. Confirmed real 2026-08-16 on a 64-callee
        # dispatcher: max_pseudocode_lines=200 cut 522 of 722 real body
        # lines, silently dropping 22 of 39 real callee names from both the
        # pseudocode AND the (then-capped) neighbour-summary section at once.
        # These three are lists of short items (~10-60 chars each: an API
        # name, a string literal, a function name) -- cheap per-entry
        # compared to a pseudocode line or a full-sentence summary, so a
        # tight cap buys very little context savings while risking the same
        # silent-signal-loss failure mode as max_pseudocode_lines above.
        # `_imports`/`_strings`/`_indirect_refs` (idapro_client.py) used to
        # duplicate these caps at extraction time too, before a config value
        # here could even take effect -- fixed 2026-08-16 (extraction now
        # always captures everything real; these are the only place
        # truncation happens). Kept as generous, not literal-infinite,
        # defaults -- still a real sanity bound against a truly degenerate
        # function.
        "max_imported_apis_shown": 15,
        "max_referenced_strings_shown": 12,
        "max_code_referrers_shown": 5,
        # NOT a cap on neighbour summaries -- every direct callee/caller
        # that has a real KB entry is always shown, in full, uncapped (a
        # cap-at-5 here was tried 2026-08-16 and reverted: it traded real
        # per-function evidence for prompt-size economy, the wrong trade for
        # a dispatcher with dozens of genuine direct children). This only
        # bounds the tail of neighbours with NO KB entry yet -- those carry
        # no content beyond "not yet analyzed", so a long list of them is
        # filler, unlike a real summary.
        "max_unanalyzed_neighbours_shown": 5,
        "max_call_site_snippet_lines": 20,
        "max_related_summary_chars": 160,
    },
    "policy": {
        # Names worth spending an LLM call on. Only still-unnamed `sub_`
        # functions are candidates; named functions (library/symbol/import/
        # analyst) and trivial auto stubs (j_/nullsub_/locret_/loc_) are not --
        # analyzing them wastes calls. An explicit `-f` target bypasses this.
        "analysis_candidate_prefixes": ["sub_"],
        # Placeholder names safe to OVERWRITE at apply time -- broader than the
        # candidate set: every IDA auto-generated name. The tool's own `maybe_`
        # hedge and IDA's `unknown_libname_` stub are added in
        # RenamePolicy._is_provisional; real recovered names stay protected.
        "auto_generated_prefixes": [
            "sub_", "j_", "nullsub_", "locret_", "loc_",
        ],
        "vague_names_blacklist": [
            "process_data", "handle_stuff", "helper", "wrapper",
            "unknown_function", "do_something", "function", "func",
            "handle", "process", "execute", "run", "init", "cleanup",
            "setup", "teardown", "main_func", "common_func",
            "utility_func", "generic_func", "sub_routine", "routine",
            "method", "callback", "handler", "handler_func",
            "do_work", "work", "task", "operation", "perform",
            "check", "get_data", "set_data", "read_data", "write_data",
        ],
        "conflict_suffix_max": 9,
    },
    "scoring": {
        "sink_bonus": 3,
        "input_reachable_bonus": 5,
        "low_complexity_bonus": 2,
        "low_complexity_threshold": 5,
        # Added 2026-08-13 -- see scorer.py's module docstring for why a
        # large, rarely-called function needs its own bonus (mutually
        # exclusive with low_complexity_bonus, not additive with it).
        "high_complexity_bonus": 3,
        "high_complexity_threshold": 20,
        "high_complexity_caller_max": 3,
        "xref_focus_thresholds": {
            "focused_max": 3,
            "focused_bonus": 4,
            "moderate_max": 10,
            "moderate_bonus": 1,
            "utility_min": 51,
            "utility_penalty": 2,
            "heavy_utility_min": 201,
            "heavy_utility_penalty": 5,
        },
        # `mapview.suspicious()` widens its candidate pool to `top *
        # candidate_pool_multiplier` before `top_scored`/`unnamed_only`
        # trim it back down to `top` -- same "consider more than you show"
        # pattern as search.semantic_candidate_pool_multiplier below.
        "candidate_pool_multiplier": 3,
    },
    "graph": {
        "dangerous_sinks": [
            "memcpy", "memmove", "strcpy", "strcat", "sprintf", "vsprintf",
            "gets", "recv", "recvfrom", "read", "malloc", "realloc", "free",
        ],
        "input_sink_apis": [
            "recv", "recvfrom", "read", "fgets", "fread",
            "WSARecv", "ReadFile", "getchar", "scanf", "fscanf",
        ],
        # Per-node caps on CallGraphBuilder's own import/string/constant
        # lists -- separate from the per-function prompt caps above (this is
        # graph-annotation data, e.g. mapview/scoring, not what gets sent to
        # the LLM). dangerous_sink_calls detection itself is NOT capped by
        # these -- it's collected before the truncation, so a sink call can
        # never silently disappear from risk detection.
        "max_import_refs_per_node": 20,
        "max_string_refs_per_node": 20,
        "max_constant_operands_per_node": 64,
    },
    "kb": {
        "refinement_confidence_skip": 0.85,
        # Safety cap on repair_naming_conflicts()'s re-scan loop -- was a
        # bare literal (refiner.py) with no override anywhere. Healthy runs
        # converge (a round that fixes nothing) well before this; it only
        # matters as a backstop against pathological back-and-forth on an
        # unusual binary, so a run that hits it deserves the ability to
        # raise it without editing code.
        "repair_max_rounds": 5,
    },
    "diff": {
        # Above this prompt size, take a second independent sample of
        # compare_functions and check agreement before trusting a single
        # verdict. Real motivating case (2026-08-11): the largest pair in an
        # ntfs.sys diff run (~60000 prompt chars) got three qualitatively
        # different verdicts (low-risk refactor twice, then a medium-risk
        # bounds-check finding) across otherwise-identical runs at
        # temperature 0.1 -- exactly the case where getting it right matters
        # most. Small/simple prompts are cheap enough to leave alone.
        "self_consistency_min_prompt_chars": 20000,
        # Model to use for the reconciliation call when two samples
        # disagree. None reuses the primary model; set to a larger locally
        # installed model (e.g. "gpt-oss:20b") to get a second opinion from
        # a different model, not just a second roll of the same one.
        "tiebreak_model": None,
        # Ollama `think` override for the tiebreak call specifically (see
        # OllamaClient docstring -- gpt-oss needs this set to null/None,
        # not False, or it returns garbage under format=json).
        "tiebreak_think": False,
    },
    "search": {
        # Below this cosine similarity, `ask` reports "no confident match"
        # instead of padding the list with the least-bad-of-a-bad-bunch.
        # Raised from 0.45 (2026-08-13): a live validation pass against a
        # real 526-function knowledge base found 0.45 didn't leave enough
        # margin -- a deliberately nonsensical query ("render a 3D graphics
        # scene using OpenGL shaders", nothing to do with the target binary)
        # still scored 0.456-0.466 and silently returned noise-cluster
        # functions instead of "no confident match". Every genuine #1 hit
        # across 8 real test queries landed at 0.65+, so the floor only
        # trims long-tail secondary results, never the actual answer -- set
        # at 0.55, not just above the measured nonsense ceiling, because
        # this config's own purpose is precision over recall ("don't pad
        # with least-bad-of-a-bad-bunch"), and a plausible-but-unconfident
        # query (e.g. asking about a capability the sample doesn't actually
        # have) is better served by an honest "no confident match" than by
        # four weakly-related results presented with the same formatting as
        # a real hit. One nonsense-query data point, not an exhaustively
        # tuned constant; revisit if a wider set of negative-control
        # queries says otherwise.
        "min_similarity": 0.55,
        # Small additive nudge so a risk-oriented question surfaces the
        # actually dangerous function over a low-risk near-duplicate that
        # merely shares more vocabulary -- applied on top of, not baked into,
        # the semantic similarity score.
        "risk_boost": {"low": 0.0, "medium": 0.03, "high": 0.07},
        "security_relevant_boost": 0.02,
        # `semantic_query` fetches top_k * this many candidates from the
        # embedder before min_similarity/dedup trim back down to top_k --
        # widening the pool first is what lets the floor and dedup passes
        # actually have something to filter.
        "semantic_candidate_pool_multiplier": 4,
    },
}

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def defaults() -> dict:
    """The full merged default config, before any user file is applied."""
    return _deep_merge(_TUNING_DEFAULTS, _USER_DEFAULTS)


def load_config(config_path: str | None = None) -> dict:
    """
    Load config.json merged over the built-in defaults.

    Never raises — a missing or malformed file falls back to defaults.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    config = defaults()

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            config = _deep_merge(config, user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[wingman] Warning: could not load {path}: {e}. Using defaults.")

    return config
