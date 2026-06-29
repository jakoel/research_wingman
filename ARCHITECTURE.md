# research-helper — Architecture

This document is the authoritative design reference.
Implementation decisions that contradict it should update it, not ignore it.

---

## 1. Goals

Turn a stripped, unknown binary into a **ranked, semantically-annotated knowledge base**
that a vulnerability researcher can query by intent rather than by address.

The key insight driving every design choice:

> A 50 000-function binary becomes ~200 functions once you filter to semantically
> interesting code. The pipeline's job is that filtering — fast and automatically.
> Elite researchers do this in hours; novices spend weeks reading logging code.

The xref technique at the core: functions called from 50+ places are utility
functions. Functions called from 1–3 places in sensitive code are where bugs live.
This is encoded directly in the scoring formula (§4).

---

## 2. System Overview

### Full pipeline mode (default)

```
idapro.open_database("target.i64", run_auto_analysis=False)
      │
      │  IDA Python API (idautils, idc, ida_funcs, ida_hexrays, ida_gdl, ida_nalt)
      ▼
┌──────────────┐
│  Phase 1     │  call_graph.py          Build annotated call graph
│  Graph       │  → call_graph.json      Cache to disk
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Phase 2     │  scorer.py              Score every function
│  Order       │  (in-memory)            Kahn topo-sort, score as tiebreaker
└──────┬───────┘
       │  bottom-up ordered worklist
       ▼
┌──────────────┐
│  Phase 3     │  main.py + prompts.py   LLM analysis per function
│  LLM         │  → knowledge_base.sqlite  Inject callee summaries from KB
└──────┬───────┘    → call_edges (in KB)   Write result to KB after each call
       │
       ▼
┌──────────────┐
│  Phase 4     │  refiner.py             One top-down pass
│  Refine      │  (updates KB in-place)  Re-query with caller context
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Phase 5     │  embedder.py            Embed summaries → FAISS index
│  Index       │  → kb_vectors.faiss     (triggered by --build-index only)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Phase 6     │  query.py               Researcher queries
│  Query       │  (reads KB + FAISS)     Semantic search / call chains
└──────────────┘

idapro.close_database()   ← renames (idc.set_name) and comments (idc.set_func_cmt) flushed here
```

### Quick / standalone mode (--quick or --function)

```
idapro.open_database("target.i64", run_auto_analysis=False)
      │
      ▼
┌──────────────┐
│  Phase 3     │  LLM analysis (no callee context injection)
│  LLM only   │  → knowledge_base.sqlite
└──────────────┘
      │  --apply: idc.set_name + idc.set_func_cmt per function
      ▼
idapro.close_database()
```

Phases 1, 2, and 4 are skipped entirely. Useful for:
- Testing LLM output on a specific function before running the full pipeline
- Quickly renaming known interesting functions by name or address
- Running without needing the full graph build overhead

`--function NAME ...` implies `--quick` automatically.

**Dependencies between phases:**
- Phase 1 uses IDA Python API directly. Result cached to `call_graph.json`.
- Phase 2 reads the Phase 1 cache. Does not call IDA API.
- Phase 3 reads KB entries written by earlier Phase 3 iterations (callee summary injection). In quick mode, graph is None so callee injection is skipped.
- Phase 4 reads Phase 3 KB entries and writes back to the same rows. Skipped in quick mode.
- Phase 5 reads Phase 3/4 KB entries. Triggered only by `--build-index`.
- Phase 6 reads Phase 3/4 KB entries and the Phase 5 FAISS index.

---

## 3. File Map

```
research-helper/
├── main.py               Phases 1–4 orchestration + CLI
├── query.py              Phase 6 query CLI (separate command)
├── requirements.txt      faiss-cpu, numpy
├── ARCHITECTURE.md       This file
│
└── llm_renamer/
    ├── __init__.py
    ├── config.json        User-editable defaults (all tunable parameters)
    ├── config.py          Config loader with deep-merge over defaults
    │
    │   ── IDA layer ──────────────────────────────────────────────────
    ├── idapro_client.py   IDA Python API client + FunctionContextExtractor
    │                      Caches import map and string map for sharing with Phase 1
    │
    │   ── graph layer ───────────────────────────────────────────────
    ├── call_graph.py      Phase 1: CallNode, CallGraph, CallGraphBuilder, load_or_build
    │                      Single-pass over all instructions (edges + imports + strings)
    │
    │   ── scoring ────────────────────────────────────────────────────
    ├── scorer.py          Phase 2: score_node, depth_from_leaves, build_worklist
    │
    │   ── LLM layer ──────────────────────────────────────────────────
    ├── prompts.py         SYSTEM_PROMPT + build_user_prompt (callee injection)
    ├── llm_client.py      Ollama /api/chat client (stdlib urllib)
    ├── validator.py       LLM output validation + snake_case sanitisation
    │
    │   ── knowledge base ─────────────────────────────────────────────
    ├── kb.py              Phase 3/4/5: SQLite read/write, address normalisation
    ├── embedder.py        Phase 5: FAISS IndexFlatIP, Ollama embed API
    │
    │   ── refinement ────────────────────────────────────────────────
    ├── refiner.py         Phase 4: top-down refinement pass
    │
    │   ── rename application ────────────────────────────────────────
    ├── renamer.py         Rename policy + idc.set_name wrapper
    │
    │   ── persistence ────────────────────────────────────────────────
    ├── audit.py           Append-only JSONL audit log
    ├── checkpoint.py      Atomic JSON checkpoint (per-address done flag)
    └── review.py          Review JSON writer/reader
```

---

## 4. Scoring Formula

Every function receives a score before analysis begins. Higher score = higher
processing priority. Score drives both the Kahn topological sort tiebreaker
and LLM budget cutoff decisions.

```
score(f) =
    depth_from_nearest_leaf(f)      # 0 for leaves, +1 per hop up the call tree
  + sink_bonus                      # +3  if f calls any dangerous sink import
  + input_reachable_bonus           # +5  if f is input_reachable (§5.1)
  + complexity_bonus                # +2  if cyclomatic_complexity(f) ≤ 5
  + xref_focus_score(f)             # signed weight — the elite filtering lens
```

**Cyclomatic complexity** is approximated as `max(0, basic_block_count - 1)`.
Low complexity → straightforward code → higher LLM confidence → better callee
summaries for callers.

### Xref focus score

```
caller_count   xref_focus_score   Rationale
─────────────  ─────────────────  ──────────────────────────────────────────
1 – 3          +4                 Unique code path; bugs live here
4 – 10         +1                 Moderately shared; still interesting
11 – 50         0                 Neutral
51 – 200       −2                 Likely utility (string ops, logging, math)
201+           −5                 Definitely utility; deprioritise aggressively
```

**The invariant:** xref filtering is a weight, not a hard filter. A function with
`input_reachable=true` (+5) and `caller_count=300` (−5) nets 0 — it stays in the
queue but does not jump ahead of focused functions. Never discard a function solely
on caller count.

### Depth from nearest leaf

`depth_from_leaves(graph)` computes this iteratively: leaves start at 0, then
each node receives `min(callee_depths) + 1`. Nodes in cycles and any unreachable
nodes default to 0. The result is a `dict[int, int]` keyed by address.

### Worklist construction (`build_worklist`)

Kahn's topological sort on the call graph where "in-degree" counts unprocessed
callees (so leaves become ready first). A max-heap (`heapq`) breaks ties by score
descending. Any addresses involved in cycles are appended after acyclic nodes,
sorted by score. The result is a `list[int]` of addresses in bottom-up,
score-weighted order.

---

## 5. Phase 1 — Call Graph (`call_graph.py`)

### 5.1 Data model

```python
@dataclass
class CallNode:
    address: int
    name: str
    size_bytes: int
    basic_block_count: int
    caller_count: int = 0
    callee_addresses: list[int] = field(default_factory=list)
    dangerous_sink_calls: list[str] = field(default_factory=list)
    input_reachable: bool = False
    string_refs: list[str] = field(default_factory=list)
    import_refs: list[str] = field(default_factory=list)

class CallGraph:
    nodes: dict[int, CallNode]        # address (int) → CallNode
    edges: list[tuple[int, int]]      # [(caller_addr, callee_addr), ...]
    def callees_of(addr: int) -> list[int]
    def callers_of(addr: int) -> list[int]
    def save(path: str) -> None       # atomic write via .tmp
    def load(path: str) -> CallGraph  # classmethod
```

### 5.2 Build sequence (`CallGraphBuilder.build`)

1. `idautils.Functions()` → enumerate all function entry addresses
2. `_single_pass()` → **one pass over all instructions** via `idautils.FuncItems` + `idautils.XrefsFrom`:
   - Internal call edges: code xrefs to addresses in `func_addrs`
   - Import refs: code xrefs to addresses in the import map
   - Dangerous-sink calls: import refs whose name is in `dangerous_sinks`
   - String refs: data xrefs to addresses in the string cache
3. `_annotate_caller_counts` — increment `caller_count` from edges
4. `_annotate_callee_lists` — populate `callee_addresses` from edges
5. `_annotate_basic_blocks` — `ida_gdl.FlowChart(func)` per function
6. `_annotate_input_reachable` — BFS forward from input-API seed functions

### 5.3 Single-pass annotation

The builder shares the `FunctionContextExtractor`'s import cache and string cache.
Both caches are built lazily on first use and reused across Phase 1 (graph build)
and Phase 3 (context extraction), so they are never constructed twice.

**Import detection:** a code xref from an instruction to an address that appears
in the import map is counted as an import call. Import map is built via
`ida_nalt.get_import_module_qty()` / `ida_nalt.enum_import_names()`.

**String detection:** the string map is built from `idautils.Strings()`. Any data
xref from an instruction to an address in the string map is a string reference.

**Edge detection:** a code xref from an instruction to any address in `func_addrs`
(the set of all function start addresses) is counted as an internal call edge.
This correctly handles direct calls and tail calls; indirect calls through
import stubs are excluded because import addresses are not in `func_addrs`.

### 5.4 `input_reachable` — definition and BFS direction

Seed functions = functions whose `import_refs` contain any name from `input_sink_apis`
(`recv`, `read`, `fgets`, `fread`, `WSARecv`, `ReadFile`, `getchar`, `scanf`, `fscanf`).

BFS direction: **forward (callee direction)** from seeds. A function is marked
`input_reachable=true` if it is reachable by following call edges starting from
a seed. This marks all functions in the input-processing call tree.

Overapproximation (false positives) is acceptable. This is a scoring signal, not
a security verdict.

### 5.5 Cache

The graph is serialised to JSON via `graph.save(path)` (atomic `.tmp` swap).
`load_or_build(extractor, config, cache_path, force_rebuild=False)` loads from
cache if present; rebuilds and re-saves if not. Pass `force_rebuild=True` (or
`--rebuild-graph` CLI flag) to discard the cache.

JSON format:
```json
{
  "nodes": { "4198400": { "address": 4198400, "name": "sub_401000", ... } },
  "edges": [[4198400, 4199000], ...]
}
```

Note: JSON object keys are strings (required by JSON spec), so addresses appear
as decimal strings in the file but are stored as integers in memory.

---

## 6. IDA Python API Layer (`idapro_client.py`)

### 6.1 FunctionContextExtractor

The single interface between all pipeline phases and the open IDA database.
All IDA Python modules (`idautils`, `idc`, `ida_funcs`, etc.) are imported
**lazily inside methods** — the module itself can be imported before
`idapro.open_database()` is called.

| Method | IDA API used |
|---|---|
| `get_all_auto_functions()` | `idautils.Functions()`, `idc.get_func_name()`, `ida_funcs.get_func()` |
| `get_functions_by_name(targets)` | `idc.get_name_ea_simple()`, `ida_funcs.get_func()` |
| `get_function_count()` | `ida_funcs.get_func_qty()` |
| `extract(func_row)` | all extractors below |
| `name_exists(name)` | `idc.get_name_ea_simple()` |
| `_pseudocode(ea)` | `ida_hexrays.decompile(ea)` → `str(cfunc)` |
| `_strings(ea)` | `idautils.FuncItems()`, `idautils.XrefsFrom()`, string cache |
| `_imports(ea)` | `idautils.FuncItems()`, `idautils.XrefsFrom()`, import cache |
| `_callees(ea)` | `idautils.FuncItems()`, `idautils.XrefsFrom()`, `ida_funcs.get_func()` |
| `_callers(ea)` | `idautils.XrefsTo()`, `ida_funcs.get_func()` |
| `_comments(ea)` | `idc.get_cmt(ea, 0/1)` |
| `_basic_blocks(ea)` | `ida_funcs.get_func()`, `ida_gdl.FlowChart()` |

### 6.2 Shared caches

| Cache | Built by | Used by |
|---|---|---|
| `_import_map()` | `ida_nalt.get_import_module_qty/enum_import_names` | Phase 1 (graph build), Phase 3 (imports extractor) |
| `_string_map()` | `idautils.Strings()` | Phase 1 (graph build), Phase 3 (strings extractor) |

Both are built once and stored on the extractor instance. `CallGraphBuilder`
receives the extractor and calls `extractor._import_map()` / `extractor._string_map()`
directly.

### 6.3 Targeted function mode (`--function`)

`get_functions_by_name(targets)` accepts a mix of names and hex addresses:
- If a target starts with `0x`, it is parsed as a hex integer address.
- Otherwise `idc.get_name_ea_simple(target)` resolves the name.
- The resolved address is passed to `ida_funcs.get_func()` to get the canonical
  function start and size.
- Unresolvable targets produce a warning and are skipped.

In `run_analysis`, when `target_functions` is set:
- The checkpoint is bypassed — every specified function is re-analyzed.
- The auto-generated prefix filter is bypassed — any named function can be targeted.

### 6.4 Rename application and IDA annotation

```python
idc.set_name(ea, new_name, idc.SN_NOCHECK)   # rename
idc.set_func_cmt(ea, summary, 1)              # repeatable comment (visible in callers)
```

`SN_NOCHECK` skips IDA's name-validity check (the validator in `validator.py`
already enforces snake_case rules). Both calls happen inside `RenamePolicy.apply_rename()`
when `--apply` is set and a summary was produced by the LLM. Changes are flushed
to disk by `idapro.close_database()`.

The comment is **repeatable** (`repeatable=1`) so it appears in the IDA listing
at every call site, not just at the function definition — making the LLM's
analysis immediately visible while browsing callers.

---

## 7. Phase 3 — LLM Analysis (`main.py` + `prompts.py`)

### 7.1 Analysis loop (per function, in worklist order)

```
1. KB skip check     — if kb.is_phase3_done(addr):  skip
2. Checkpoint skip   — if checkpoint.is_done(ea):   skip  (bypassed in targeted mode)
3. Extract context   — FunctionContextExtractor.extract()
4. Guard: pseudocode — skip if missing or < min_pseudocode_lines
5. Limit check       — if llm_calls_this_run >= limit: break
6. Callee injection  — kb.get_callee_summaries(graph.callees_of(ea))
7. Build prompt      — build_user_prompt(ctx, callee_kb_entries)
8. LLM call          — OllamaClient.analyze(SYSTEM_PROMPT, user_prompt)
9. KB write          — always, after every successful LLM call (see §7.2)
10. Validate rename  — validate_llm_output(raw_response, config)
11. Apply rename     — only if --apply and validation passed
12. Mark checkpoint  — checkpoint.mark_done(ea)
```

Step 9 happens **before** step 10. A function whose rename is rejected still gets
its `summary`, `security_relevant`, and `interesting_behaviors` stored in the KB.
This matters because rejected functions are still callees of other functions and
their summaries are useful for Phase 3 context injection.

LLM errors (network or JSON parse) are **not checkpointed** — the function will
be retried on the next run.

### 7.2 --limit behaviour

`--limit N` is checked at step 5, **after** pseudocode guards but **before** the
LLM call. This means:
- Functions skipped by checkpoint, KB, or missing pseudocode do not count toward the limit.
- The limit counts actual LLM calls made in the current run.
- The checkpoint is written after each LLM call (step 12), so a clean break at
  the limit leaves a fully consistent checkpoint for the next run.

### 7.3 KB entry written per function

```json
{
  "address":               "0x401000",
  "old_name":              "sub_401000",
  "new_name":              "parse_http_header",
  "confidence":            0.87,
  "summary":               "Parses an HTTP/1.1 request header into a fixed-size buffer without bounds checking.",
  "security_relevant":     true,
  "interesting_behaviors": ["Copies user-controlled length via memcpy", "No bounds check visible"],
  "callee_summaries_used": ["read_next_token", "to_lower_ascii"],
  "caller_count":          2,
  "score":                 14.0,
  "phase3_done":           true,
  "phase4_refined":        false
}
```

### 7.4 LLM output schema

```json
{
  "should_rename":       true,
  "suggested_name":      "parse_http_header",
  "confidence":          0.87,
  "reason":              "1–2 sentence evidence-based explanation",
  "risk":                "low|medium|high",
  "summary":             "One sentence describing what the function does.",
  "security_relevant":   true,
  "interesting_behaviors": ["observation 1", "observation 2"],
  "evidence": {
    "strings":   ["Content-Length:"],
    "apis":      ["recv", "memcpy"],
    "behavior":  ["Reads from socket", "Copies to stack buffer"]
  }
}
```

---

## 8. Phase 4 — Refinement (`refiner.py`)

**One pass only. No looping.**

For each function in the KB where `phase3_done=1` and `phase4_refined=0`:

1. **Skip** if `confidence >= refinement_confidence_skip` (default 0.85).
2. **Skip** if no callers of this function are found in the KB.
3. Re-query the LLM with the original summary + up to 5 caller summaries.
4. If `changed=true` in the response: update `new_name`, `summary`,
   `confidence`, `security_relevant`, `interesting_behaviors` in-place.
5. Set `phase4_refined=1` regardless of whether the answer changed.

---

## 9. Phase 5 — Knowledge Base and Vector Index

### 9.1 SQLite schema (`kb.py`)

```sql
CREATE TABLE functions (
    address               TEXT PRIMARY KEY,   -- "0xABCD" hex string
    old_name              TEXT NOT NULL,
    new_name              TEXT,
    confidence            REAL,
    summary               TEXT,
    security_relevant     INTEGER DEFAULT 0,
    interesting_behaviors TEXT,               -- JSON array
    callee_summaries_used TEXT,               -- JSON array
    caller_count          INTEGER DEFAULT 0,
    score                 REAL DEFAULT 0,
    phase3_done           INTEGER DEFAULT 0,
    phase4_refined        INTEGER DEFAULT 0,
    embedding_id          TEXT
);

CREATE TABLE call_edges (
    caller_address  TEXT NOT NULL,
    callee_address  TEXT NOT NULL,
    PRIMARY KEY (caller_address, callee_address)
);
```

Database opened with `PRAGMA journal_mode=WAL` for concurrent read safety.

**Address format:** all addresses stored as `"0xABCD"` (uppercase hex, `0x` prefix).

### 9.2 FAISS vector index (`embedder.py`)

- Model: `nomic-embed-text` via Ollama (configurable via `kb.embed_model`)
- Index type: `faiss.IndexFlatIP` — flat inner-product index
- Vectors are L2-normalised before add/search (inner product = cosine similarity)
- Two files: `kb_vectors.faiss` (binary) + `kb_vectors.faiss.map` (JSON address list)

---

## 10. Phase 6 — Query CLI (`query.py`)

| Flag | Mode | Mechanism |
|---|---|---|
| `"<text>"` | Semantic search | FAISS cosine similarity; falls back to confidence ranking if no index |
| `--report` | Security report | All `security_relevant=1` entries, sorted by confidence |
| `--chain ADDR` | Call chain | `kb.get_call_chain(addr, depth=4)` walking `call_edges` |
| `--score-report` | Score ranking | Loads `call_graph.json`, runs `scorer.score_report()`, no KB needed |
| `--no-vector` | Confidence rank | Skips FAISS; sorts all Phase 3 entries by confidence |

---

## 11. Configuration Reference

All fields are in `llm_renamer/config.json`. All scoring weights are config-driven.

```json
{
  "ollama": {
    "url": "http://localhost:11434",
    "model": "codellama:13b-instruct",
    "timeout_seconds": 120,
    "temperature": 0.1,
    "num_ctx": 8192
  },

  "analysis": {
    "confidence_threshold": 0.65,
    "max_name_length": 64,
    "min_pseudocode_lines": 3,
    "max_pseudocode_lines": 200,
    "skip_high_risk": true
  },

  "policy": {
    "never_overwrite_analyst_names": true,
    "auto_generated_prefixes": ["sub_", "j_", "nullsub_", "locret_", "loc_"],
    "vague_names_blacklist": ["..."],
    "conflict_suffix_max": 9
  },

  "scoring": {
    "sink_bonus": 3,
    "input_reachable_bonus": 5,
    "low_complexity_bonus": 2,
    "low_complexity_threshold": 5,
    "xref_focus_thresholds": {
      "focused_max": 3,        "focused_bonus": 4,
      "moderate_max": 10,      "moderate_bonus": 1,
      "utility_min": 51,       "utility_penalty": 2,
      "heavy_utility_min": 201,"heavy_utility_penalty": 5
    }
  },

  "graph": {
    "cache_filename": "call_graph.json",
    "dangerous_sinks": ["memcpy", "memmove", "strcpy", "strcat", "sprintf",
                        "vsprintf", "gets", "recv", "recvfrom", "read",
                        "malloc", "realloc", "free"],
    "input_sink_apis": ["recv", "recvfrom", "read", "fgets", "fread",
                        "WSARecv", "ReadFile", "getchar", "scanf", "fscanf"]
  },

  "kb": {
    "sqlite_filename": "knowledge_base.sqlite",
    "faiss_filename": "kb_vectors.faiss",
    "embed_model": "nomic-embed-text",
    "refinement_confidence_skip": 0.85
  },

  "output": {
    "dir": null,
    "review_filename":    "llm_renames_review.json",
    "audit_filename":     "llm_renames_audit.jsonl",
    "checkpoint_filename":"llm_renames_checkpoint.json"
  }
}
```

---

## 12. CLI Reference

### `main.py`

```
python main.py --database PATH [options]

Required:
  --database PATH        Path to the .i64 IDA database

Configuration:
  --config PATH          config.json path  (default: llm_renamer/config.json)
  --ollama-url URL       override Ollama URL (e.g. http://remote-host:11434)
  --model NAME           override model name
  --out-dir DIR          directory for all output files  (default: cwd)

Function selection:
  --function NAME ...    analyze only these functions; implies --quick
  --limit N              stop after N LLM calls; checkpoint saves progress
  --quick                skip Phases 1/2/4 (graph, scoring, refinement)

Run modes:
  (none)                 Review mode — analyse, write review JSON, no renames
  --apply                Analyse, apply renames, and write IDA function comments
  --apply-file PATH      Apply from an existing review JSON (no LLM, no graph)

Pipeline control:
  --rebuild-graph        Discard call_graph.json cache and rebuild
  --skip-refine          Skip Phase 4 refinement pass
  --build-index          Build FAISS vector index after analysis (Phase 5)

Checkpoint:
  --clear-checkpoint     Reset checkpoint and exit
  --no-resume            Ignore checkpoint; reprocess all functions
```

**Output files** (all in `--out-dir`):

| File | Written by | Purpose |
|---|---|---|
| `call_graph.json` | Phase 1 | Cached annotated call graph |
| `knowledge_base.sqlite` | Phase 3/4 | Per-function LLM results |
| `kb_vectors.faiss` + `.map` | Phase 5 (--build-index) | FAISS vector index |
| `llm_renames_review.json` | Phase 3 | Human-readable rename proposals |
| `llm_renames_audit.jsonl` | Phase 3 | Append-only audit trail |
| `llm_renames_checkpoint.json` | Phase 3 | Processed address set |

### `query.py`

```
python query.py [options] [query_text]

  query_text             Free-text semantic query

  --config PATH          config.json path
  --kb PATH              override knowledge base path
  --index PATH           override FAISS index path
  --out-dir DIR          directory containing output files
  --top N                number of results  (default: 20)
  --security-only        restrict to security_relevant=true functions
  --no-vector            skip FAISS; rank by confidence instead
  --chain ADDR           show call chain for a hex address (e.g. 0x401000)
  --report               print all security-relevant functions by confidence
  --score-report         print top functions by score (reads call_graph.json)
```

---

## 13. Invariants and Quality Rules

1. **Never rename with confidence < 0.6** without flagging for human review.

2. **Uncertain callee summaries are labelled, not silently injected.**
   Any callee with `confidence < 0.6` gets `[LOW CONFIDENCE X.XX]` in the prompt.

3. **One refinement pass.** Phase 4 runs exactly once per function.

4. **`security_relevant=true` has a narrow definition.** The function must
   demonstrably touch user-controlled data or perform memory operations without
   visible bounds checks. Proximity is not sufficient.

5. **Analyst names are never overwritten** unless the user explicitly targets the
   function with `--function`. IDA function comments written on apply are
   repeatable so they appear at every call site.

6. **Xref filtering is a weight, not a hard cutoff.**

7. **KB write happens before rename validation.** Summary and security fields
   are independent of the rename decision and valuable for callee injection.

8. **Address format is canonical hex.** All KB primary keys are `"0xABCD"`
   (uppercase hex, `0x` prefix).

---

## 14. Dependencies

```
Python >= 3.9  (run from IDA's bundled Python or any env with idapro importable)
idapro         Installed alongside IDA Pro 9+
faiss-cpu >= 1.7.4    (Phase 5/6 only — pip install faiss-cpu numpy)
numpy >= 1.24.0       (required by faiss-cpu)
```

All other modules use Python stdlib only. Phases 1–4 run without faiss-cpu.

External services required at runtime:
- `ollama` with a chat model (Phase 3) and an embed model (Phase 5)
  — can run on a remote host; pass `--ollama-url` to specify the address

---

## 15. Constraints and Non-Goals

- **IDA Pro / idapro only.** No Ghidra or Binary Ninja backend. A future backend
  would need to implement the `FunctionContextExtractor` interface.
- **Auto-generated names only** (by default). Named functions are not renamed but
  their summaries can still be written to the KB for callee context. Use `--function`
  to bypass the prefix filter for individual functions.
- **No taint analysis.** `input_reachable` is a call-graph heuristic, not a
  dataflow analysis.
- **Not a vulnerability proof.** The output is a prioritised reading list with
  semantic annotations. A human researcher confirms findings.
- **No fuzzing harness generation.** Out of scope.
