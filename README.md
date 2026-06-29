# llm_renamer

Renames auto-generated IDA Pro function names (`sub_*`, `j_*`, `nullsub_*`, …) using a locally-running LLM.  
Opens the `.i64` database directly via **idapro** 

---

## How it works

```
idapro.open_database("target.i64")
  │
  │  IDA Python API (idautils, idc, ida_hexrays)
  ▼
llm_renamer (this tool)
  1. Enumerate sub_* / j_* / nullsub_* functions
  2. For each: extract pseudocode, strings, imports, callers, callees
  3. Send context to Ollama → receive JSON rename suggestion
  4. Validate suggestion (confidence, risk, name rules)
  5. Review mode  → write proposals to JSON file, no DB changes
     Apply mode   → idc.set_name(ea, new_name) into the open database
                    (changes are saved when the database closes)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **IDA Pro 9+** with **idapro** | `idapro` is IDA's headless Python package. Installed alongside IDA Pro. |
| **Hex-Rays decompiler** | Required for pseudocode. Part of IDA Pro (separate license). |
| **Ollama** | Local LLM server. `ollama.com`. Can run on the same or a remote machine. |
| **Python 3.9+** | Run from IDA's bundled Python or any Python environment where `idapro` is importable. |

---

## 1. Install Ollama and pull a model

```bash
# Install Ollama: https://ollama.com
ollama pull codellama:13b-instruct
```

Any instruction-following model works. Larger code models give better rename quality.  
If Ollama runs on a different machine, pass `--ollama-url http://<host>:11434` at runtime.

---

## 2. Configure

Edit **`llm_renamer/config.json`**:

```json
{
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
| `ollama.url` | `http://localhost:11434` | Ollama server address (can be a remote host) |
| `ollama.model` | `codellama:13b-instruct` | Ollama model name |
| `analysis.confidence_threshold` | `0.65` | Minimum LLM confidence to accept a rename |
| `analysis.skip_high_risk` | `true` | Reject suggestions the LLM marks as high-risk |
| `policy.never_overwrite_analyst_names` | `true` | Never rename non-auto-generated names |
| `policy.auto_generated_prefixes` | `["sub_","j_","nullsub_","locret_","loc_"]` | Names matching these are eligible for renaming |

---

## 3. Run

### Quick / standalone mode *(for testing or targeting specific functions)*

```bash
python main.py --database target.i64 --function sub_1c0012232
python main.py --database target.i64 --function sub_1c0012232 --apply
python main.py --database target.i64 --function 0x1c0012232 sub_401000
```

`--function` implies `--quick` automatically. The call graph build, scoring, and refinement passes are all skipped — the tool goes straight to LLM analysis for the specified function(s) and returns in seconds. Accepts names or hex addresses. Works on any function, not just auto-generated ones.

Use `--quick` without `--function` to run the full function list without the graph overhead:

```bash
python main.py --database target.i64 --quick
```

### Full pipeline mode *(for bulk analysis of a binary)*

**Review mode** *(default — no database changes)*

```bash
python main.py --database /path/to/target.i64
```

Builds the call graph, scores all functions, analyzes every `sub_*` / `j_*` / `nullsub_*` in bottom-up order, and writes a review file. The database is not modified.

**Apply mode** *(writes renames and IDA comments into the .i64)*

```bash
python main.py --database target.i64 --apply
```

Same as review mode but also calls `idc.set_name()` for every approved rename and writes the LLM summary as a repeatable function comment (`idc.set_func_cmt`), visible in the IDA listing and in callers. Changes are saved when the database closes. Prompts for confirmation before starting.

**Process only a batch** *(useful for large binaries)*

```bash
python main.py --database target.i64 --limit 200
```

Stops after 200 LLM calls. The checkpoint is saved automatically; the next run picks up where this one left off.

**Ollama on a remote host**

```bash
python main.py --database target.i64 --ollama-url http://192.168.1.50:11434
```

**Apply from a previous review file** *(no LLM calls)*

```bash
python main.py --database target.i64 --apply-file llm_renames_review.json
```

Reads an existing review JSON and applies only the approved renames.

**Reset progress**

```bash
python main.py --database target.i64 --clear-checkpoint
```

### All CLI options

```
python main.py --database PATH [options]

Required:
  --database PATH        Path to the .i64 IDA database file

Configuration:
  --config PATH          Path to config.json  (default: llm_renamer/config.json)
  --ollama-url URL       Override Ollama server URL (e.g. http://remote-host:11434)
  --model NAME           Override Ollama model name
  --out-dir DIR          Output directory (default: current working directory)

Function selection:
  --function NAME ...    Analyze only these function(s); implies --quick
  --limit N              Stop after N LLM calls; checkpoint saves progress
  --quick                Skip call graph, scoring, and refinement (Phases 1/2/4)

Run modes:
  (none)                 Review mode — analyze and write review JSON, no renames
  --apply                Analyze and apply approved renames + IDA comments
  --apply-file PATH      Apply from an existing review JSON (no LLM calls)

Pipeline control:
  --rebuild-graph        Discard call_graph.json cache and rebuild
  --skip-refine          Skip Phase 4 top-down refinement pass
  --build-index          Build FAISS vector index after analysis (Phase 5)

Checkpoint:
  --clear-checkpoint     Reset checkpoint and exit
  --no-resume            Ignore checkpoint; reprocess all functions
```

---

## Output files

All files are written to the current directory (or `--out-dir`).

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

Append-only JSON Lines log. One record per processed function, including skips, rejections, and failures.

```jsonl
{"ts":"2026-05-09T12:00:01Z","address":"0x401A30","old_name":"sub_401A30","suggested_name":"decrypt_aes_block","final_name":"decrypt_aes_block","confidence":0.87,"risk":"low","reason":"...","applied":true,"rejection_reason":"","error":""}
{"ts":"2026-05-09T12:00:02Z","address":"0x401B00","old_name":"sub_401B00","suggested_name":"helper","final_name":"","confidence":0.72,"risk":"low","reason":"...","applied":false,"rejection_reason":"Name is too vague: 'helper'","error":""}
```

### `llm_renames_checkpoint.json`

Set of already-processed addresses. Enables safe interruption and resumption — rerun the same command and it picks up where it left off.

---

## Rename policy

- **Only auto-generated names** are eligible by default (`sub_*`, `j_*`, `nullsub_*`, `locret_*`, `loc_*`). Use `--function` to target any function regardless of name.
- **Analyst-created names are never overwritten** (`never_overwrite_analyst_names: true`)
- **Rejected automatically if**: confidence below threshold · risk is `high` · name is vague · name contains illegal characters · name starts with a digit · name is longer than 64 characters
- **Conflict resolution**: if the suggested name already exists, appends `_2`, `_3`, … up to suffix limit

---

## Project layout

```
llm_renamer/
  config.json          User-editable configuration
  config.py            Config loader with defaults and deep-merge
  idapro_client.py     IDA Python API context extraction (pseudocode, xrefs, strings, imports)
  call_graph.py        Phase 1: call graph construction and caching
  scorer.py            Phase 2: function scoring and bottom-up worklist ordering
  llm_client.py        Ollama HTTP client (stdlib urllib, no extra dependencies)
  validator.py         LLM output validation and snake_case sanitization
  renamer.py           Safe rename policy (idc.set_name wrapper)
  prompts.py           System prompt and per-function user prompt builder
  kb.py                SQLite knowledge base (Phases 3/4/5)
  embedder.py          Phase 5: FAISS vector index via Ollama embeddings
  refiner.py           Phase 4: top-down refinement pass
  audit.py             Append-only JSON Lines audit logger
  checkpoint.py        Atomic-replace checkpoint for resumable runs
  review.py            Review JSON writer and reader

main.py                CLI entry point (Phases 1–5)
query.py               Phase 6 query CLI
README.md              This file
ARCHITECTURE.md        Full design reference
```

---

## Troubleshooting

**`database not found`**  
Check the path passed to `--database`. The file must exist and be a valid `.i64`.

**`Ollama is not reachable`**  
Run `ollama run codellama:13b-instruct` to start the server. If Ollama is on another machine, pass `--ollama-url http://<host>:11434` and ensure the port is reachable from the VM.

**`No Hex-Rays pseudocode available`** (logged for many functions)  
Your IDA installation does not include the Hex-Rays decompiler, or the binary architecture is not supported. Functions without pseudocode are skipped and logged.

**`not found in database: 'sub_...'`** (when using `--function`)  
The name was not found via `idc.get_name_ea_simple`. Double-check the exact spelling. You can also pass the hex address directly: `--function 0x1c0012232`.

**Interrupted run**  
Just rerun the same command. The checkpoint ensures already-processed functions are skipped.

**Want to reprocess everything**  
Run `python main.py --database target.i64 --clear-checkpoint` then rerun.

---

## Planned

- **Call chain generation**: forward traversal from all entry points (`main`, `WinMain`, `DllMain`, TLS callbacks), output as Markdown with indented call tree. Intended to feed document ranking against CVE text corpora.
