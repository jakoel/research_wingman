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

### Map is free; the LLM is not

The governing constraint is that LLM calls are the scarce resource. A local
13B model takes seconds per function, so a few thousand functions is an
overnight run — and most of a binary is CRT glue, logging and utility code that
is not worth a call.

The call graph, by contrast, is built in one pass over the instructions and
annotates every function with the triage signal (sinks called, input
reachability, referenced strings and imports, caller count). That is free.

So the system splits in two:

```
MAP      navigate.py + mapview.py     no LLM, no IDA once cached.
         Entry points, scoring, search, call paths, neighbourhoods.
         Produces a *selection* of addresses.
                    │
                    ▼
ANALYZE  pipeline.py                  spends LLM calls on that selection.
         Requires an explicit scope. Prices it before spending.
```

`analyze` with no scope is an error, not a full run. `--all` still exists but
is the last option in every menu and help listing.

### The command surface

```
rh menu    DB ──── interactive session. Opens the database once and holds it.

rh map     DB ──── reads the cached graph. No LLM, no IDA (except --build).

rh analyze DB ──── reads the database, calls the LLM, writes the workspace.
                   NEVER modifies the database.

rh apply   DB ──── reads the workspace, writes the database.
                   NEVER calls the LLM.

rh ask     DB ──── reads the workspace only. Does not open the database.
rh status  DB ──┘
```

Separating the expensive operation from the irreversible one is the whole
safety model. There is no flag that does both.

### Inside `analyze` (full mode)

```
idapro.open_database("target.i64", run_auto_analysis=False)
      │
      │  IDA Python API (idautils, idc, ida_funcs, ida_hexrays, ida_gdl, ida_nalt)
      ▼
┌──────────────┐
│  Graph       │  call_graph.py          Build annotated call graph
│              │  → call_graph.json      Cache in the workspace
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Order       │  scorer.py              Score every function
│              │  (in-memory)            Kahn topo-sort, score as tiebreaker
└──────┬───────┘
       │  bottom-up ordered worklist
       ▼
┌──────────────┐
│  LLM         │  pipeline.py + prompts.py   Analysis per function
│              │  → knowledge_base.sqlite    Inject callee summaries from KB
└──────┬───────┘    → call_edges (in KB)     Write result to KB after each call
       │
       ▼
┌──────────────┐
│  Refine      │  refiner.py             One top-down pass
│              │  (updates KB in-place)  Re-query with caller context
└──────────────┘

idapro.close_database()          ← nothing was written to the database
```

### Inside `apply`

```
idapro.open_database("target.i64", run_auto_analysis=False)
      │
      ▼
   knowledge_base.sqlite  →  rows WHERE status='approved' AND applied=0
      │
      ▼  idc.set_name + idc.set_func_cmt, then kb.mark_applied()
idapro.close_database()   ← renames and comments flushed here
```

### Quick mode (`--quick`, implied by `--function`)

Graph, scoring and refinement are skipped; the LLM step runs without callee
context injection. Useful for testing prompt output on one function, or for
targeting known-interesting functions without paying for a whole-program graph
build.

### The semantic index

Built on demand by `ask`, not by a separate command. `ask` compares the number
of vectors in `kb_vectors.faiss.map` against the number of KB rows with a
summary; if the index is missing or behind, it rebuilds before searching.
`--reindex` forces it.

**Data dependencies:**
- The graph uses the IDA API directly and caches to `call_graph.json`.
- Scoring reads the graph cache. It does not call the IDA API.
- The LLM step reads KB entries written by earlier iterations of itself
  (callee summary injection). In quick mode the graph is None, so injection is
  skipped.
- Refinement reads those KB rows and writes back to them.
- The index and all query modes read the KB.

---

## 3. File Map

```
research-helper/
├── rh.py                 The CLI: analyze / apply / ask / status / export
├── main.py               Shim mapping the old flags to the new commands
├── requirements.txt      faiss-cpu, numpy
├── ARCHITECTURE.md       This file
│
└── llm_renamer/
    ├── __init__.py
    ├── config.json        Tier-1 settings only (ollama + two thresholds)
    ├── config.py          Tier-1 + tier-2 defaults, deep-merged with the file
    ├── workspace.py       Every path derived from the database location
    │
    │   ── map layer (no LLM) ────────────────────────────────────────
    ├── navigate.py        Traversal, paths, landmarks, search, selection
    ├── mapview.py         Rendering for the map views
    │
    │   ── orchestration ─────────────────────────────────────────────
    ├── menu.py            Interactive session over the whole surface
    ├── pipeline.py        analyze() and apply() — the two IDA-facing ops
    ├── ask.py             Search, reports, status, index freshness
    │
    │   ── IDA layer ──────────────────────────────────────────────────
    ├── idapro_client.py   IDA Python API client + FunctionContextExtractor
    │                      Caches import map and string map for graph sharing
    │
    │   ── graph layer ───────────────────────────────────────────────
    ├── call_graph.py      CallNode, CallGraph, CallGraphBuilder, load_or_build
    │                      Single-pass over all instructions (edges + imports + strings)
    │
    │   ── scoring ────────────────────────────────────────────────────
    ├── scorer.py          score_node, depth_from_leaves, build_worklist
    │
    │   ── LLM layer ──────────────────────────────────────────────────
    ├── prompts.py         SYSTEM_PROMPT + build_user_prompt (callee injection)
    ├── llm_client.py      Ollama /api/chat client (stdlib urllib)
    ├── validator.py       LLM output validation + snake_case sanitisation
    │
    │   ── knowledge base ─────────────────────────────────────────────
    ├── kb.py              SQLite read/write, schema migration, address normalisation
    ├── embedder.py        FAISS IndexFlatIP, Ollama embed API
    │
    │   ── refinement ────────────────────────────────────────────────
    ├── refiner.py         Top-down refinement pass
    │
    │   ── rename application ────────────────────────────────────────
    ├── renamer.py         Rename policy + idc.set_name wrapper
    │
    │   ── persistence ────────────────────────────────────────────────
    ├── audit.py           Append-only JSONL audit log
    └── export.py          Review JSON writer (one-way view of the KB)
```

Removed in the simplification pass: `checkpoint.py` (the KB tracks progress),
`review.py` (replaced by the one-way `export.py`), and `query.py` (folded into
`rh ask`).

---

## 3a. State Model

All state for a database lives in `<database>.rh/`, resolved by
`workspace.Workspace`. Nothing reads or writes the current working directory.
This is deliberate: the previous design defaulted output to `os.getcwd()`,
so running from a different directory silently produced an empty knowledge
base and re-spent every LLM call.

**The knowledge base is the single source of truth.** One row per function
carries the proposal, the accept/reject decision, and the applied state:

```
analyzed=0                     never seen, or the last attempt errored
analyzed=1, status='rejected'  ruled out — not retried
analyzed=1, status='approved'  has a usable proposal
applied=1                      the rename is in the IDA database
```

Consequences:

- **Resume** is `WHERE phase3_done = 0`, not a separate checkpoint file.
- **Rejections are sticky**, so a rejected function costs one LLM call ever.
- **LLM errors are not sticky** — the row is left unanalyzed on purpose so a
  transient Ollama failure is retried on the next run.
- **`apply` is idempotent** — applied rows are marked and skipped.
- **`review.json` cannot drift**, because nothing ever reads it back.

`kb._migrate()` adds columns to older knowledge bases with `ALTER TABLE` and
backfills `status` from whether an analyzed row has a `new_name`. Opening an
old KB with a new build is safe and does not lose results.

A `meta` key/value table holds the observed `seconds_per_call`, folded as a
0.6/0.4 weighted average after every run. Cost quotes use it, so estimates
reflect the user's own model and hardware rather than a guess. It is stored to
four decimal places — rounding to two lost the measurement entirely on fast
setups.

---

## 3b. Scope Model

`pipeline.build_plan()` turns a scope into an ordered, priced `Plan`. Scopes
come from `navigate.py`, which only ever reads the cached graph:

| Selector | `navigate` call | Typical size |
|---|---|---|
| `-f NAME...` | direct lookup | 1–5 |
| `--callees NAME` | `descendants(graph, addr, depth)` | 5–50 |
| `--callers NAME` | `ancestors(graph, addr, depth)` | 5–50 |
| `--around NAME` | both, deduplicated | 10–100 |
| `--between A B` | `paths_between()` | 5–40 |
| `--to-sinks` | `paths_to_sinks()` | 10–60 |
| `--top N` | `top_scored()` + `unnamed_only()` | N |
| `--all` | every auto-named function | thousands |

`Plan` carries the scope size, how many are already analyzed (and therefore
skipped), and the resulting LLM-call count. `Plan.estimate()` multiplies that
by the measured `seconds_per_call`. `analyze(confirm=...)` hands the plan to
the caller — CLI prompt or menu — before anything is spent.

Path-based scopes are bounded on purpose (`max_paths`, `max_depth` in
`paths_between`): a dense call graph has effectively unlimited distinct paths,
and an unbounded search would hang rather than return a useful selection.

Ordering still runs through `build_worklist`, restricted to the selection, so
even a 7-function scope is analyzed leaves-first and gets callee summaries
injected into the prompts of its callers.

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

## 5. Call Graph (`call_graph.py`)

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
Both caches are built lazily on first use and reused across the graph build and
the per-function context extraction, so they are never constructed twice.

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
| `_import_map()` | `ida_nalt.get_import_module_qty/enum_import_names` | Graph build, imports extractor |
| `_string_map()` | `idautils.Strings()` | Graph build, strings extractor |

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
- The resume check is bypassed — every specified function is re-analyzed.
- The auto-generated prefix filter is bypassed — any named function can be targeted.

### 6.4 Rename application and IDA annotation

```python
idc.set_name(ea, new_name, idc.SN_NOCHECK)   # rename
idc.set_func_cmt(ea, summary, 1)              # repeatable comment (visible in callers)
```

`SN_NOCHECK` skips IDA's name-validity check (the validator in `validator.py`
already enforces snake_case rules). Both calls happen inside
`RenamePolicy.apply_rename()`, reached only from `pipeline.apply()` — never
during analysis. The comment is written when the KB row carries a summary.
Changes are flushed to disk by `idapro.close_database()`.

The comment is **repeatable** (`repeatable=1`) so it appears in the IDA listing
at every call site, not just at the function definition — making the LLM's
analysis immediately visible while browsing callers.

---

## 7. LLM Analysis (`pipeline.analyze` + `prompts.py`)

### 7.1 Analysis loop (per function, in worklist order)

```
1. Resume check      — if kb.is_analyzed(addr): skip   (bypassed when targeted)
2. Extract context   — FunctionContextExtractor.extract()
3. Cheap rejections  — no pseudocode, or < min_pseudocode_lines
                       → record status='rejected', no LLM call
4. Limit check       — if llm_calls >= limit: break
5. Callee injection  — kb.get_callee_summaries(graph.callees_of(ea))
6. Build prompt      — build_user_prompt(ctx, callee_kb_entries)
7. LLM call          — OllamaClient.analyze(SYSTEM_PROMPT, user_prompt)
8. Validate rename   — validate_llm_output(raw_response, config)
9. KB write          — one row carrying both the analysis and the verdict
```

There is exactly one write path (`kb.record`) and one skip condition. The
previous design checked both a checkpoint file and the KB, which could
disagree.

A function whose *rename* is rejected still gets its `summary`,
`security_relevant` and `interesting_behaviors` stored — rejected functions are
still callees of other functions, and their summaries remain useful for context
injection.

LLM errors (network or JSON parse) leave the row unanalyzed on purpose, so the
function is retried on the next run. Rejections are sticky; errors are not.

Nothing in this loop touches the IDA database.

### 7.2 --limit behaviour

`--limit N` is checked at step 4, **after** the cheap rejections but **before**
the LLM call:
- Functions skipped by resume, or rejected without an LLM call, do not count
  toward the limit.
- The limit counts actual LLM calls made in the current run.
- The KB is committed after each function, so breaking at the limit always
  leaves consistent state for the next run.

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
  "status":                "approved",
  "risk":                  "low",
  "reason":                "Reads Content-Length and memcpys into a stack buffer.",
  "evidence":              {"apis": ["recv", "memcpy"]},
  "rejection_reason":      "",
  "applied":               false,
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

## 8. Refinement (`refiner.py`)

**One pass only. No looping.** Runs at the end of a full `analyze`, unless
`--no-refine` or quick mode.

For each function in the KB where `phase3_done=1` and `phase4_refined=0`:

1. **Skip** if `confidence >= refinement_confidence_skip` (default 0.85).
2. **Skip** if no callers of this function are found in the KB.
3. Re-query the LLM with the original summary + up to 5 caller summaries.
4. If `changed=true` in the response: update `new_name`, `summary`,
   `confidence`, `security_relevant`, `interesting_behaviors` in-place.
5. Set `phase4_refined=1` regardless of whether the answer changed.

---

## 9. Knowledge Base and Vector Index

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
    phase3_done           INTEGER DEFAULT 0,  -- exposed as `analyzed`
    phase4_refined        INTEGER DEFAULT 0,  -- exposed as `refined`
    embedding_id          TEXT,
    -- added when the KB became the single source of truth:
    status                TEXT,               -- 'approved' | 'rejected'
    risk                  TEXT,
    reason                TEXT,
    evidence              TEXT,               -- JSON object
    rejection_reason      TEXT,
    applied               INTEGER DEFAULT 0,
    applied_name          TEXT,
    analyzed_at           TEXT
);

CREATE TABLE call_edges (
    caller_address  TEXT NOT NULL,
    callee_address  TEXT NOT NULL,
    PRIMARY KEY (caller_address, callee_address)
);
```

Database opened with `PRAGMA journal_mode=WAL` for concurrent read safety.

**Address format:** all addresses stored as `"0xABCD"` (uppercase hex, `0x` prefix).

**Column naming:** `phase3_done` and `phase4_refined` keep their original names
so that knowledge bases built by earlier versions keep working. Every method
and every dict key exposed outside `kb.py` uses `analyzed` / `refined`.

**Migration:** `_migrate()` compares `PRAGMA table_info` against
`_ADDED_COLUMNS` and issues `ALTER TABLE ADD COLUMN` for anything missing. When
`status` is newly added it is backfilled — an analyzed row with a `new_name`
becomes `approved`, one without becomes `rejected` — because that is exactly
what the old schema encoded implicitly. Without the backfill, `apply` would
silently find nothing to do on an existing KB.

### 9.2 FAISS vector index (`embedder.py`)

- Model: `nomic-embed-text` via Ollama (configurable via `ollama.embed_model`)
- Index type: `faiss.IndexFlatIP` — flat inner-product index
- Vectors are L2-normalised before add/search (inner product = cosine similarity)
- Two files: `kb_vectors.faiss` (binary) + `kb_vectors.faiss.map` (JSON address list)
- `Embedder(config, index_path)` takes its path from the Workspace, not config
- Freshness is `len(map) >= count(rows with a summary)`. `ask` rebuilds when
  that fails, so there is no user-visible index-building step

---

## 10. Query Modes (`ask.py`)

None of these open the IDA database.

| Flag | Mode | Mechanism |
|---|---|---|
| `"<text>"` | Semantic search | FAISS cosine similarity; auto-builds a stale/missing index; falls back to confidence ranking if faiss is unavailable |
| `--report` | Security report | All `security_relevant=1` entries, sorted by confidence |
| `--chain ADDR` | Call chain | `kb.get_call_chain(addr, depth=4)` walking `call_edges` |
| `--scores` | Score ranking | Loads `call_graph.json`, runs `scorer.score_report()`, no KB needed |
| `--no-vector` | Confidence rank | Skips FAISS; sorts all analyzed entries by confidence |
| `--reindex` | Force rebuild | Re-embeds every summary |

`rh status` reads the same sources and reports counts, staleness, and the
command to run next.

---

## 11. Configuration Reference

Two tiers, both defined in `llm_renamer/config.py`.

**Tier 1 — shipped in `config.json`.** The settings a user is expected to edit:

```json
{
  "ollama": {
    "url": "http://localhost:11434",
    "model": "codellama:13b-instruct",
    "embed_model": "nomic-embed-text"
  },
  "analysis": {
    "confidence_threshold": 0.65,
    "skip_high_risk": true
  }
}
```

**Tier 2 — code defaults in `_TUNING_DEFAULTS`.** Not in `config.json`, but any
key can be overridden by adding it there; `load_config` deep-merges the file
over the defaults.

| Group | Keys |
|---|---|
| `ollama` | `timeout_seconds`, `temperature`, `num_ctx` |
| `analysis` | `max_name_length`, `min_pseudocode_lines`, `max_pseudocode_lines` |
| `policy` | `never_overwrite_analyst_names`, `auto_generated_prefixes`, `vague_names_blacklist`, `conflict_suffix_max` |
| `scoring` | `sink_bonus`, `input_reachable_bonus`, `low_complexity_bonus`, `low_complexity_threshold`, `xref_focus_thresholds.*` |
| `graph` | `dangerous_sinks`, `input_sink_apis` |
| `kb` | `refinement_confidence_skip` |

**Paths are not configurable.** Every filename that used to live under
`output.*`, `graph.cache_filename`, `kb.sqlite_filename` and
`kb.faiss_filename` is now derived by `workspace.Workspace` from the database
path. `--workspace DIR` relocates the whole directory if needed.

---

## 12. CLI Reference

The interactive session is the primary interface; subcommands exist for
scripting. `rh.py` rewrites its own argv so the session is the default:

```
rh.py                  → discover a .i64 in the cwd, then `menu <that>`
rh.py target.i64       → `menu target.i64`
rh.py map target.i64   → unchanged
```

`_normalize_argv()` prepends `menu` whenever the first argument is neither a
known command nor a flag. Everything the CLI can do is reachable from the
session, including maintenance (rebuild graph, rebuild index, switch model,
delete results) — the session must never print a flag the user would have to
exit and retype.

```
python rh.py COMMAND DATABASE [options]

Commands:
  menu      Interactive session. Opens the database once and holds it.
  map       Browse the cached graph. No LLM; no IDA except --build.
  analyze   Analyze a scope with the LLM. Never modifies the database.
  apply     Write approved renames into the database. Never calls the LLM.
  ask       Search the analysis. Does not open the database.
  status    Report progress and what to run next.
  export    Write the knowledge base to a review JSON file.

Common to every command:
  DATABASE               Path to the .i64 IDA database (positional)
  --workspace DIR        State directory  (default: <database>.rh)
  --config PATH          config.json path (default: llm_renamer/config.json)

analyze / ask / menu also accept:
  --ollama-url URL       Override the Ollama server URL
  --model NAME           Override the Ollama model

map:
  --build                Build or refresh the call graph (needs IDA, no LLM)
  --suspicious [N]       Highest-scoring unnamed functions (default 25)
  --find QUERY           Search names, referenced strings, imported APIs
  --explore NAME         One function: neighbours, strings, imports, sinks
  --paths [N]            Entry point -> memory sink paths (default 10)

analyze  (exactly one scope selector is REQUIRED):
  -f, --function NAME…   These functions, by name or 0xADDR
  --callees NAME         It and what it calls, --depth hops down
  --callers NAME         It and what calls it, --depth hops up
  --around NAME          Both directions
  --between FROM TO      Every function on the call paths between two
  --to-sinks             Paths from entry points down to memory sinks
  --top N                The N highest-scoring unnamed functions
  --all                  Every auto-named function (the overnight run)

  --depth N              Hops for --callees/--callers/--around (default 2)
  --start NAME           Root --to-sinks somewhere other than entry points
  --limit-paths N        How many sinks --to-sinks traces (default 10)
  --limit N              Stop after N LLM calls; rerun to continue
  --redo                 Re-analyze functions that were already done
  -y, --yes              Skip the cost confirmation prompt
  --quick                Skip the call graph, scoring and refinement
  --rebuild-graph        Discard the cached call graph
  --no-refine            Skip the top-down refinement pass
  --reset                Discard all previous results for this database

apply:
  --dry-run              Show what would change; write nothing
  --min-confidence F     Raise the confidence bar for this run

ask:
  QUERY                  Free-text question (position-independent)
  --top N                Result count  (default: 20)
  --security-only        Only security_relevant entries
  --chain ADDR           Call chain below a hex address
  --report               All security-relevant functions
  --scores               Highest-scoring functions from the call graph
  --no-vector            Rank by confidence instead of similarity
  --reindex              Force a semantic index rebuild

export:
  -o, --out PATH         Output path  (default: <workspace>/review.json)
```

`ask` accepts its question before or after other flags. Argparse cannot bind a
second optional positional across an intervening flag, so `main()` uses
`parse_known_args` and folds stray non-flag words into the query; leftover
tokens starting with `-` still raise an error.

**Output files** (all in `<database>.rh/`):

| File | Written by | Purpose |
|---|---|---|
| `knowledge_base.sqlite` | `analyze`, `apply` | All state — results, verdicts, applied flags |
| `call_graph.json` | `analyze` (full mode) | Cached annotated call graph |
| `kb_vectors.faiss` + `.map` | `ask` (on demand) | Semantic index |
| `audit.jsonl` | `analyze`, `apply` | Append-only trail of every action |
| `review.json` | `export` | One-way human-readable snapshot |

---

## 13. Invariants and Quality Rules

1. **Never rename with confidence < 0.6** without flagging for human review.

2. **Uncertain callee summaries are labelled, not silently injected.**
   Any callee with `confidence < 0.6` gets `[LOW CONFIDENCE X.XX]` in the prompt.

3. **One refinement pass.** Refinement runs exactly once per function.

4. **`security_relevant=true` has a narrow definition.** The function must
   demonstrably touch user-controlled data or perform memory operations without
   visible bounds checks. Proximity is not sufficient.

5. **Analyst names are never overwritten.** `--function` bypasses the prefix
   filter for *analysis*, but `apply` re-checks the database's current name at
   write time and refuses anything an analyst has since named. IDA function
   comments written on apply are repeatable so they appear at every call site.

6. **Xref filtering is a weight, not a hard cutoff.**

7. **The analysis is stored whether or not the rename is accepted.** Summary
   and security fields are independent of the rename decision and valuable for
   callee injection.

8. **Address format is canonical hex.** All KB primary keys are `"0xABCD"`
   (uppercase hex, `0x` prefix), normalised by `kb._addr_to_hex`.

9. **`analyze` never writes to the IDA database; `apply` never calls the LLM.**
   No flag combines them. This is what makes the expensive operation safe to
   rerun and the irreversible one cheap to preview.

10. **State is derived from the database path, never from the cwd.** Anything
    that reintroduces `os.getcwd()` as a default output location is a bug.

11. **No LLM call happens without a quoted, confirmable scope.** `analyze`
    requires a scope selector; `build_plan` prices it; `confirm` can decline.
    A change that lets analysis start implicitly is a bug, not a convenience.

12. **The map layer never calls the LLM or opens IDA.** `navigate.py` and
    `mapview.py` read the cached graph and the KB only. That is what makes
    browsing instant and free, which is what makes targeted spending possible.

---

## 14. Dependencies

```
Python >= 3.9  (run from IDA's bundled Python or any env with idapro importable)
idapro         Installed alongside IDA Pro 9+
faiss-cpu >= 1.7.4    (semantic search only — pip install faiss-cpu numpy)
numpy >= 1.24.0       (required by faiss-cpu)
```

All other modules use Python stdlib only. `analyze` and `apply` run without
faiss-cpu; `ask` degrades to confidence ranking.

Every module carries `from __future__ import annotations` — the codebase uses
PEP 604 `X | None` syntax and must import cleanly on Python 3.9.

External services required at runtime:
- `ollama` with a chat model (`analyze`) and an embed model (`ask`)
  — can run on a remote host; pass `--ollama-url` to specify the address

---

## 15. Constraints and Non-Goals

- **IDA Pro / idapro only.** No Ghidra or Binary Ninja backend. A future backend
  would need to implement the `FunctionContextExtractor` interface.
- **Auto-generated names only** (by default). Named functions are not renamed but
  their summaries can still be written to the KB for callee context. Use
  `-f/--function` to analyze individual functions regardless of their name.
- **No taint analysis.** `input_reachable` is a call-graph heuristic, not a
  dataflow analysis.
- **Not a vulnerability proof.** The output is a prioritised reading list with
  semantic annotations. A human researcher confirms findings.
- **No fuzzing harness generation.** Out of scope.
