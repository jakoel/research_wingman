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
        "model": "codellama:13b-instruct",
        "embed_model": "nomic-embed-text",
    },
    "analysis": {
        "confidence_threshold": 0.65,
        "skip_high_risk": True,
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
    },
    "policy": {
        "never_overwrite_analyst_names": True,
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
    },
    "kb": {
        "refinement_confidence_skip": 0.85,
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
            print(f"[rh] Warning: could not load {path}: {e}. Using defaults.")

    return config
