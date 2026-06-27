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

```
idasql server  (idasql -s target.i64 --http 8081)
      │
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
│  Index       │  → kb_vectors.faiss     (triggered by --build-index)
└──────┬───────┘    → kb_vectors.faiss.map
       │
       ▼
┌──────────────┐
│  Phase 6     │  query.py               Researcher queries
│  Query       │  (reads KB + FAISS)     Semantic search / call chains
└──────────────┘
```

**Dependencies between phases:**
- Phase 2 reads the Phase 1 cache. It does not query idasql.
- Phase 3 reads KB entries written by earlier Phase 3 iterations (callee summary injection).
- Phase 4 reads Phase 3 KB entries and writes back to the same rows.
- Phase 5 reads Phase 3/4 KB entries. Can run independently after Phase 3.
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
    │   ── idasql layer ──────────────────────────────────────────────
    ├── idasql_client.py   HTTP client + response parser + FunctionContextExtractor
    │
    │   ── graph layer ───────────────────────────────────────────────
    ├── call_graph.py      Phase 1: CallNode, CallGraph, CallGraphBuilder, load_or_build
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
    ├── renamer.py         Rename policy + idasql UPDATE
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

1. `SELECT address, name, size, end_ea FROM funcs` → all function nodes
2. `_fetch_edges()` → all internal call edges (see §5.3)
3. `_annotate_caller_counts` — increment `caller_count` from edges
4. `_annotate_callee_lists` — populate `callee_addresses` from edges
5. `_annotate_dangerous_sinks` — query imports JOIN xrefs JOIN instructions
6. `_annotate_import_refs` — all imports called by each function
7. `_annotate_string_refs` — all string literals xref'd by each function
8. `_annotate_basic_blocks` — `SELECT func_ea, COUNT(*) FROM blocks GROUP BY func_ea`
9. `_annotate_input_reachable` — BFS forward from input-API seed functions

### 5.3 Edge extraction strategy

Primary (uses `instructions` table — fast, indexed):
```sql
SELECT DISTINCT i.func_addr AS caller, x.to_ea AS callee
FROM xrefs x
JOIN instructions i ON i.address = x.from_ea
JOIN funcs f ON f.address = x.to_ea
WHERE x.is_code = 1 AND i.func_addr IS NOT NULL AND i.func_addr != x.to_ea
```

Fallback (range join — used if `instructions` table is unavailable):
```sql
SELECT DISTINCT f1.address AS caller, f2.address AS callee
FROM funcs f1
JOIN xrefs x ON x.from_ea >= f1.address AND x.from_ea < f1.end_ea
JOIN funcs f2 ON f2.address = x.to_ea
WHERE x.is_code = 1 AND f1.address != f2.address
```

The graph builder uses a **separate idasql client** with `graph.timeout_seconds`
(default 300 s) because aggregate queries over large binaries can exceed the
standard 30 s idasql timeout.

### 5.4 `input_reachable` — definition and BFS direction

Seed functions = functions that directly call a known input-ingestion API
(`recv`, `read`, `fgets`, `fread`, `WSARecv`, `ReadFile`, `getchar`, `scanf`, `fscanf`).

BFS direction: **forward (callee direction)** from seeds. A function is marked
`input_reachable=true` if it is reachable by following call edges starting from
a seed. This marks all functions in the input-processing call tree — the functions
most likely to handle user-controlled data.

Overapproximation (false positives) is acceptable. This is a scoring signal, not
a security verdict.

### 5.5 Cache

The graph is serialised to JSON via `graph.save(path)` (atomic `.tmp` swap).
`load_or_build(db, config, cache_path, force_rebuild=False)` loads from cache
if present; rebuilds and re-saves if not. Pass `force_rebuild=True` (or
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

## 6. Phase 3 — LLM Analysis (`main.py` + `prompts.py`)

### 6.1 Analysis loop (per function, in worklist order)

```
1. KB skip check     — if kb.is_phase3_done(addr):  skip
2. Checkpoint skip   — if checkpoint.is_done(ea):   skip
3. Extract context   — idasql_client.FunctionContextExtractor.extract()
4. Guard: pseudocode — skip if missing or < min_pseudocode_lines
5. Callee injection  — kb.get_callee_summaries(graph.callees_of(ea))
6. Build prompt      — build_user_prompt(ctx, callee_kb_entries)
7. LLM call          — OllamaClient.analyze(SYSTEM_PROMPT, user_prompt)
8. KB write          — always, after every successful LLM call (see §6.2)
9. Validate rename   — validate_llm_output(raw_response, config)
10. Apply rename      — only if --apply and validation passed
11. Mark checkpoint  — checkpoint.mark_done(ea)
```

Step 8 happens **before** step 9. A function whose rename is rejected still gets
its `summary`, `security_relevant`, and `interesting_behaviors` stored in the KB.
This matters because rejected functions are still callees of other functions and
their summaries are useful for Phase 3 context injection.

LLM errors (network or JSON parse) are **not checkpointed** — the function will
be retried on the next run.

### 6.2 KB entry written per function

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

Call edges are also written to the `call_edges` table after each function so
Phase 6 can reconstruct call chains without the graph cache.

### 6.3 Callee summary injection (`prompts.py`)

`build_user_prompt(ctx, callee_kb_entries=None)` replaces the bare "Internal
callees:" name list with structured summaries when KB entries exist:

```
Internal callees (already analyzed):
  parse_chunk_length [security-relevant] — Parses hex chunk-size; returns -1 on overflow.
  alloc_buffer — Wraps malloc; returns NULL on failure; no size validation.
  sub_401500  [LOW CONFIDENCE 0.42] Possibly initialises a linked list node.
  sub_401900  (not yet analyzed)
```

- `confidence < 0.6` entries are labelled `[LOW CONFIDENCE X.XX]` so the caller's
  LLM analysis explicitly knows the callee data is uncertain.
- Callees not yet in the KB are shown with `(not yet analyzed)`.
- Up to 5 not-yet-analyzed callees are shown after the KB entries.

### 6.4 LLM output schema

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

`summary`, `security_relevant`, `interesting_behaviors` are requested in the
system prompt but are **not** in `_REQUIRED` in `validator.py` — they are
optional KB fields. The rename decision depends only on the original required
fields.

`security_relevant=true` when the function demonstrably reads user-controlled
data OR performs memory operations without visible bounds checks. The LLM sets
this; the pipeline does not override it.

---

## 7. Phase 4 — Refinement (`refiner.py`)

**One pass only. No looping.**

For each function in the KB where `phase3_done=1` and `phase4_refined=0`:

1. **Skip** if `confidence >= refinement_confidence_skip` (default 0.85) —
   high-confidence results rarely change from caller context.
2. **Skip** if no callers of this function are found in the KB —
   nothing new to inject.
3. Re-query the LLM with the original summary + up to 5 caller summaries.
4. If `changed=true` in the response: update `new_name`, `summary`,
   `confidence`, `security_relevant`, `interesting_behaviors` in-place.
5. Set `phase4_refined=1` regardless of whether the answer changed.

Refinement system prompt asks the LLM to respond with `changed=false` if nothing
meaningfully improves, avoiding unnecessary KB writes.

---

## 8. Phase 5 — Knowledge Base and Vector Index

### 8.1 SQLite schema (`kb.py`)

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

CREATE INDEX idx_security   ON functions(security_relevant);
CREATE INDEX idx_confidence ON functions(confidence);
CREATE INDEX idx_score      ON functions(score DESC);
CREATE INDEX idx_phase3     ON functions(phase3_done);
```

Database opened with `PRAGMA journal_mode=WAL` for concurrent read safety.

**Address format:** all addresses stored as `"0xABCD"` (uppercase hex, `0x`
prefix). The `_addr_to_hex()` normaliser handles int → hex, hex string →
canonical, and decimal string → hex, so callers can pass any form.

### 8.2 Key KB methods

| Method | Purpose |
|---|---|
| `upsert(entry)` | Insert or update a function entry (ON CONFLICT DO UPDATE) |
| `get(address)` | Retrieve one entry by address (any format) |
| `is_phase3_done(address)` | Fast done-check for the analysis loop skip |
| `get_callee_summaries(addrs)` | Retrieve KB entries for callee injection |
| `get_callers_in_kb(addr, callers)` | Retrieve KB entries for refinement |
| `get_unrefined(skip_confidence)` | All Phase 4 candidates |
| `get_all_for_embedding()` | All entries with a non-null summary |
| `update_after_refinement(...)` | Phase 4 targeted update |
| `get_call_chain(addr, depth)` | Recursive callee walk for Phase 6 display |
| `upsert_edge(caller, callee)` / `flush()` | Write call edges in batches |

### 8.3 FAISS vector index (`embedder.py`)

- Model: `nomic-embed-text` via Ollama (configurable via `kb.embed_model`)
- Index type: `faiss.IndexFlatIP` — flat inner-product index
- Vectors are L2-normalised before add/search, so inner product = cosine similarity
- Two files on disk: `kb_vectors.faiss` (binary) + `kb_vectors.faiss.map` (JSON
  list mapping FAISS row index → address string)
- Embed API: tries `/api/embed` (Ollama 0.3+) first; falls back to `/api/embeddings`
- Each entry is embedded as:
  `"Function: {name} | Summary: {summary} | Behaviors: {behavior1}; {behavior2}"`
- Index is rebuilt from scratch by `--build-index`; incremental update not implemented

---

## 9. Phase 6 — Query CLI (`query.py`)

### 9.1 Query modes

| Flag | Mode | Mechanism |
|---|---|---|
| `"<text>"` | Semantic search | FAISS cosine similarity; falls back to confidence ranking if no index |
| `--report` | Security report | All `security_relevant=1` entries, sorted by confidence |
| `--chain ADDR` | Call chain | `kb.get_call_chain(addr, depth=4)` walking `call_edges` table |
| `--score-report` | Score ranking | Loads `call_graph.json`, runs `scorer.score_report()`, no KB needed |
| `--no-vector` | Confidence rank | Skips FAISS; sorts all Phase 3 entries by confidence |

### 9.2 Semantic search fallback

If the FAISS index file does not exist, `run_semantic_query` prints a notice and
calls `run_confidence_query` instead. No crash; results are just less semantically
ranked.

### 9.3 Output format (semantic search)

```
Query: "user-controlled length without bounds check"
────────────────────────────────────────────────────────────────────────
  #  1  0x401000       parse_http_header                         conf=0.87 [SECURITY]  sim=0.891
         Parses an HTTP/1.1 request header into a fixed-size buffer without bounds checking.
         • Copies user-controlled length via memcpy
         • No bounds check visible before copy
  #  2  0x402300       read_multipart_boundary                   conf=0.79 [SECURITY]  sim=0.843
         ...
────────────────────────────────────────────────────────────────────────
  N result(s) returned.
```

---

## 10. Configuration Reference

All fields are in `llm_renamer/config.json`. All scoring weights are config-driven
— there are no magic numbers in code.

```json
{
  "idasql": {
    "url": "http://localhost:8081",
    "timeout_seconds": 30
  },

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
    "timeout_seconds": 300,
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

## 11. CLI Reference

### `main.py`

```
python main.py [options]

Core options:
  --config PATH          config.json path  (default: llm_renamer/config.json)
  --idasql-url URL       override idasql URL
  --ollama-url URL       override Ollama URL
  --model NAME           override model name
  --out-dir DIR          directory for all output files  (default: cwd)

Run modes:
  (none)                 Review mode — analyse, write review JSON, no renames
  --apply                Analyse and apply approved renames to idasql
  --apply-file PATH      Apply from an existing review JSON (no LLM, no graph)

Pipeline control:
  --rebuild-graph        Discard call_graph.json cache and rebuild from idasql
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

  query_text             Free-text semantic query (optional if using --report etc.)

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

## 12. Invariants and Quality Rules

1. **Never rename with confidence < 0.6** without flagging for human review.
   The threshold in `config.json` (`analysis.confidence_threshold`) is 0.65 by default.

2. **Uncertain callee summaries are labelled, not silently injected.**
   Any callee with `confidence < 0.6` gets `[LOW CONFIDENCE X.XX]` in the prompt.
   The caller's analysis explicitly accounts for uncertain input.

3. **One refinement pass.** Phase 4 runs exactly once. `phase4_refined=1` is set
   on every candidate regardless of outcome; there is no retry loop.

4. **`security_relevant=true` has a narrow definition.** The function must
   demonstrably touch user-controlled data or perform memory operations without
   visible bounds checks. Proximity to such code is not sufficient.

5. **Analyst names are never overwritten.** `policy.never_overwrite_analyst_names=true`
   protects any name not matching an auto-generated prefix pattern.

6. **Xref filtering is a weight, not a hard cutoff.** A utility function called
   by security-critical code should stay in the queue — its score is reduced, not
   zeroed. If LLM budget runs out, cut from the bottom of the worklist.

7. **KB write happens before rename validation.** A function whose suggested name
   is rejected still has its `summary` and `security_relevant` stored. These fields
   are independent of the rename and are valuable for callee injection.

8. **Address format is canonical hex.** All KB primary keys are `"0xABCD"` strings
   (uppercase hex, `0x` prefix). The `_addr_to_hex()` normaliser in `kb.py`
   converts any input form. Never store decimal-format addresses in the KB.

---

## 13. Dependencies

```
Python >= 3.9
faiss-cpu >= 1.7.4    (Phase 5/6 only — install: pip install faiss-cpu numpy)
numpy >= 1.24.0       (required by faiss-cpu)
```

All other modules use Python stdlib only (`sqlite3`, `json`, `urllib`, `heapq`,
`dataclasses`). Phases 1–4 and the rename path run without faiss-cpu installed.
Phases 5–6 (`--build-index`, semantic queries in `query.py`) require it and will
print a clear install message if it is missing.

External services required at runtime:
- `idasql` HTTP server (for Phases 1 and 3)
- `ollama` with a chat model (for Phase 3 LLM calls) and an embed model (for Phase 5)

---

## 14. Constraints and Non-Goals

- **IDA / idasql only.** No Ghidra or Binary Ninja backend. A future backend
  would need to implement the `FunctionContextExtractor` interface and the call
  graph queries in `call_graph.py`.
- **Auto-generated names only.** Phase 3 only renames functions matching
  `auto_generated_prefixes`. Named functions are not renamed — but their
  summaries can still be written to the KB and used as callee context.
- **No taint analysis.** `input_reachable` is a call-graph heuristic, not a
  dataflow analysis. For precise taint tracking, post-process the KB output
  with angr or a similar tool.
- **Not a vulnerability proof.** The output is a prioritised reading list with
  semantic annotations. A human researcher confirms findings.
- **No fuzzing harness generation.** Out of scope; a future `harness_gen.py`
  can consume Phase 6 output.
