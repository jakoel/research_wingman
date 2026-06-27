# llm_renamer

Renames auto-generated IDA Pro function names (`sub_*`, `j_*`, `nullsub_*`, …) using a locally-running LLM.  
Works by querying a live IDA database through **idasql** over HTTP — no IDAPython, no IDA plugin installation required.

---

## How it works

```
IDA Pro (headless)
  └── idasql --http 8081          ← serves SQL queries against the .i64 database
        │
        │  POST /query  (SQL)
        ▼
  llm_renamer (this tool)
    1. SELECT all sub_* / j_* / nullsub_* functions
    2. For each: SELECT pseudocode, strings, imports, callers, callees
    3. Send context to Ollama → receive JSON rename suggestion
    4. Validate suggestion (confidence, risk, name rules)
    5. Review mode  → write proposals to JSON file, no DB changes
       Apply mode   → UPDATE funcs SET name = '...' WHERE address = ea
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **IDA Pro 9+** | Required. idasql is built against IDA SDK 9.0+. |
| **Hex-Rays decompiler** | Required for pseudocode. Part of IDA Pro (separate license). |
| **idasql** | Exposes the IDA database as a SQL HTTP server. See below. |
| **Ollama** | Local LLM server. `ollama.com` |
| **Python 3.9+** | Standard library only — no pip install needed. Runs outside IDA using your system Python, not IDA's bundled Python. |

---

## 1. Install idasql

idasql exposes IDA Pro's internal database as 30+ live SQL virtual tables, including a `pseudocode` table backed by Hex-Rays.

**Repository:** https://github.com/allthingsida/idasql

Follow the build instructions in the idasql README for your platform. Once built, the binary is a standalone executable.

---

## 2. Install Ollama and pull a model

```bash
# Install Ollama: https://ollama.com
ollama pull codellama:13b-instruct
```

Any instruction-following model works. Larger code models give better rename quality.  
Update `llm_renamer/config.json` if you use a different model name.

---

## 3. Configure

Edit **`llm_renamer/config.json`**:

```json
{
  "idasql": {
    "url": "http://localhost:8081",
    "timeout_seconds": 30
  },
  "ollama": {
    "url": "http://localhost:11434",
    "model": "codellama:13b-instruct",
    "temperature": 0.1
  },
  "analysis": {
    "confidence_threshold": 0.65,
    "skip_high_risk": true
  }
}
```

Key settings:

| Key | Default | Description |
|---|---|---|
| `idasql.url` | `http://localhost:8081` | idasql HTTP server address |
| `ollama.model` | `codellama:13b-instruct` | Ollama model name |
| `analysis.confidence_threshold` | `0.65` | Minimum LLM confidence to accept a rename |
| `analysis.skip_high_risk` | `true` | Reject suggestions the LLM marks as high-risk |
| `policy.never_overwrite_analyst_names` | `true` | Never rename non-auto-generated names |
| `policy.auto_generated_prefixes` | `["sub_","j_","nullsub_","locret_","loc_"]` | Names matching these are eligible for renaming |

---

## 4. Run

### Step 1 — Start idasql against your database

```bash
idasql -s /path/to/target.i64 --http 8081
```

This starts a headless IDA session and exposes it as an HTTP server.  
Hex-Rays is loaded automatically if your IDA installation includes it.  
Leave this running while llm_renamer executes.

### Step 2 — Run llm_renamer

**Review mode** *(default — no database changes)*

```bash
python main.py
```

Queries every `sub_*` / `j_*` / `nullsub_*` function, sends context to Ollama, and writes a review file. The IDA database is not modified.

**Apply mode** *(writes renames into IDA via idasql)*

```bash
python main.py --apply
```

Same as review mode but also issues `UPDATE funcs SET name = '...'` for every approved suggestion. Prompts for confirmation before starting.

**Apply from a previous review file** *(no LLM calls)*

```bash
python main.py --apply-file llm_renames_review.json
```

Reads an existing review JSON and applies only the approved renames. Useful for reviewing proposals in an editor before committing them.

**Reset progress**

```bash
python main.py --clear-checkpoint
```

Deletes the checkpoint so all functions are reprocessed on the next run.

### All CLI options

```
python main.py [options]

  --config PATH        Path to config.json  (default: llm_renamer/config.json)
  --idasql-url URL     Override idasql server URL
  --ollama-url URL     Override Ollama server URL
  --model NAME         Override Ollama model name
  --out-dir DIR        Output directory (default: current working directory)
  --apply              Analyze and apply approved renames
  --apply-file PATH    Apply from an existing review JSON (no LLM calls)
  --clear-checkpoint   Reset checkpoint and exit
  --no-resume          Ignore checkpoint; reprocess all functions
```

---

## Output files

All three files are written to the current directory (or `--out-dir`).

### `llm_renames_review.json`

Machine-readable list of every proposal. Human-reviewable before applying.

```json
{
  "generated_at": "2026-05-09T12:00:00Z",
  "stats": {
    "total_processed": 412,
    "total_proposed_approved": 198,
    "total_rejected": 183,
    "total_errors": 31
  },
  "proposals": [
    {
      "address": "0x401A30",
      "current_name": "sub_401A30",
      "suggested_name": "decrypt_aes_block",
      "confidence": 0.87,
      "risk": "low",
      "reason": "Calls AES_decrypt with a key schedule and 16-byte block pointer.",
      "evidence": {
        "strings": [],
        "apis": ["AES_decrypt", "memcpy"],
        "behavior": ["Operates on 16-byte blocks", "Uses key schedule argument"]
      },
      "validation_status": "approved",
      "rejection_reason": ""
    }
  ]
}
```

### `llm_renames_audit.jsonl`

Append-only JSON Lines log. One record per processed function, including every function that was skipped, rejected, or failed.

```jsonl
{"ts":"2026-05-09T12:00:01Z","address":"0x401A30","old_name":"sub_401A30","suggested_name":"decrypt_aes_block","final_name":"decrypt_aes_block","confidence":0.87,"risk":"low","reason":"...","applied":true,"rejection_reason":"","error":""}
{"ts":"2026-05-09T12:00:02Z","address":"0x401B00","old_name":"sub_401B00","suggested_name":"helper","final_name":"","confidence":0.72,"risk":"low","reason":"...","applied":false,"rejection_reason":"Name is too vague: 'helper'","error":""}
```

### `llm_renames_checkpoint.json`

Stores the set of already-processed function addresses. Enables safe interruption and resumption — rerun the same command after a crash or `Ctrl-C` and it picks up where it left off.

---

## Rename policy

- **Only auto-generated names** are eligible (`sub_*`, `j_*`, `nullsub_*`, `locret_*`, `loc_*`)
- **Analyst-created names are never overwritten** (`never_overwrite_analyst_names: true`)
- **Rejected automatically if**: confidence below threshold · risk is `high` · name is vague · name contains illegal characters · name starts with a digit · name is longer than 64 characters
- **Conflict resolution**: if the suggested name already exists, appends `_2`, `_3`, … up to suffix limit

---

## Project layout

```
llm_renamer/
  config.json          User-editable configuration
  config.py            Config loader with defaults and deep-merge
  idasql_client.py     HTTP client + SQL-based context extraction
  llm_client.py        Ollama HTTP client (stdlib urllib, no dependencies)
  validator.py         LLM output validation and snake_case sanitization
  renamer.py           Safe rename policy and UPDATE execution
  audit.py             Append-only JSON Lines audit logger
  checkpoint.py        Atomic-replace checkpoint for resumable runs
  review.py            Review JSON writer and reader
  prompts.py           System prompt and per-function user prompt builder

main.py                CLI entry point
README.md              This file
```

---

## idasql table reference (used by this tool)

| Table | Columns used | Purpose |
|---|---|---|
| `funcs` | `address`, `name`, `size`, `end_ea` | Enumerate functions, apply renames |
| `pseudocode` | `func_addr`, `line`, `line_num` | Hex-Rays pseudocode, one row per line (requires Hex-Rays license) |
| `decompile(ea)` | scalar function | Returns full pseudocode as a single string — primary method used by this tool |
| `strings` | `address`, `content` | String literals referenced by a function |
| `imports` | `address`, `name`, `module` | Imported API names |
| `xrefs` | `from_ea`, `to_ea`, `is_code` | Call relationships |
| `instructions` | `address`, `func_addr` | Maps instruction address → parent function |
| `blocks` | `func_ea` | Basic block count (complexity metric) |
| `names` | `address`, `name` | Global name table for conflict detection |
| `comments` | `address`, (text columns) | Analyst comments attached to a function |

---

## Planned

- **Call chain generation**: forward traversal from all entry points (`main`, `WinMain`, `DllMain`, TLS callbacks), output as Markdown with indented call tree and flat path-per-line list. Intended to feed document ranking against CVE text corpora.

---

## Troubleshooting

**`idasql is not reachable`**  
Make sure `idasql -s your_binary.i64 --http 8081` is running and the port matches `idasql.url` in config.

**`Ollama is not reachable`**  
Run `ollama run codellama:13b-instruct` to start the server and verify the model is pulled.

**`No Hex-Rays pseudocode available`** (logged for many functions)  
Your IDA installation does not include the Hex-Rays decompiler, or the binary architecture is not supported by your Hex-Rays version. Functions without pseudocode are skipped and logged.

**Interrupted run**  
Just rerun the same command. The checkpoint file ensures already-processed functions are skipped.

**Want to reprocess everything**  
Run `python main.py --clear-checkpoint` then rerun.
