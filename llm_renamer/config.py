"""Configuration loading and defaults for llm_renamer."""

import os
import json
import copy

_DEFAULTS = {
    "idasql": {
        "url": "http://localhost:8081",
        "timeout_seconds": 30,
    },
    "ollama": {
        "url": "http://localhost:11434",
        "model": "codellama:13b-instruct",
        "timeout_seconds": 120,
        "temperature": 0.1,
        "num_ctx": 8192,
    },
    "analysis": {
        "confidence_threshold": 0.65,
        "max_name_length": 64,
        "min_pseudocode_lines": 3,
        "max_pseudocode_lines": 200,
        "skip_high_risk": True,
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
    "output": {
        "dir": None,
        "review_filename": "llm_renames_review.json",
        "audit_filename": "llm_renames_audit.jsonl",
        "checkpoint_filename": "llm_renames_checkpoint.json",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(config_dir: str) -> dict:
    """
    Load config.json from config_dir, merged over built-in defaults.
    Returns the merged config dict. Never raises — falls back to defaults.
    """
    config_path = os.path.join(config_dir, "config.json")
    config = copy.deepcopy(_DEFAULTS)

    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            config = _deep_merge(config, user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[llm_renamer] Warning: failed to load config.json: {e}. Using defaults.")

    return config
