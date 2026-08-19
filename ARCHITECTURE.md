# research-wingman — Architecture

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
is the last option in every help listing.

### The command surface

```
research_wingman.py map     DB ──── reads the cached graph. No LLM, no IDA (except --build).

research_wingman.py analyze DB ──── reads the database, calls the LLM, writes the workspace.
                   NEVER modifies the database.

research_wingman.py apply   DB ──── reads the workspace, writes the database.
                   NEVER calls the LLM.

research_wingman.py ask     DB ──── reads the workspace only. Does not open the database.
research_wingman.py status  DB ──┘

research_wingman.py diff  OLD PATCHED ── reads both cached graphs (+ the LLM per
                   candidate/new/removed function). NEVER modifies either database. §16.
```

Separating the expensive operation from the irreversible one is the whole
safety model. `research_wingman.py analyze` applies by default (calls both in
sequence within one command — a UX default, see §13 invariant 9; `--no-apply`
opts out) but there is no flag, and never will be, that merges them into one
*function*: the write step is always literally `pipeline.apply()`, so
`research_wingman.py apply --dry-run` always shows the truth.

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

### The semantic index

Built on demand by `ask`, not by a separate command. `ask` compares a
content-hash of the current summaries against what's stored (not just a
vector count -- refinement can change a summary without changing how many
there are); if the index is missing or stale, it rebuilds before searching.

**Data dependencies:**
- The graph uses the IDA API directly and caches to `call_graph.json`.
- Scoring reads the graph cache. It does not call the IDA API.
- The LLM step reads KB entries written by earlier iterations of itself
  (callee summary injection). A targeted scope (`-f` and friends) with no
  cached graph yet resolves `graph=None` rather than paying for a
  whole-program build, so injection is skipped in that case.
- Refinement reads those KB rows and writes back to them.
- The index and all query modes read the KB.

---

## 3. File Map

```
research-wingman/
├── research_wingman.py   The CLI: analyze / apply / ask / status / export
├── requirements.txt      faiss-cpu, numpy
├── ARCHITECTURE.md       This file
│
└── llm_renamer/
    ├── __init__.py
    ├── config.json        Tier-1 settings, plus explicit prompt-content-cap overrides (§11)
    ├── config.py          Tier-1 + tier-2 defaults, deep-merged with the file
    ├── workspace.py       Every path derived from the database location
    │
    │   ── map layer (no LLM) ────────────────────────────────────────
    ├── navigate.py        Traversal, paths, landmarks, search, selection
    ├── mapview.py         Rendering for the map views
    │
    │   ── orchestration ─────────────────────────────────────────────
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
    ├── prompts.py         SYSTEM_PROMPT + build_user_prompt (callee/caller injection,
    │                      WPP method-name string elevation)
    ├── llm_client.py      Ollama /api/chat client (stdlib urllib)
    ├── validator.py       LLM output validation + snake_case sanitisation
    │
    │   ── knowledge base ─────────────────────────────────────────────
    ├── kb.py              SQLite read/write, schema migration, address normalisation
    ├── embedder.py        FAISS IndexFlatIP, Ollama embed API
    │
    │   ── structural family detection ──────────────────────────────
    ├── family.py           body_hash/normalize_pseudocode -- structural twin
    │                      detection shared by prompts.py and refiner.py (§7.1e, §8.2)
    │
    │   ── refinement ────────────────────────────────────────────────
    ├── refiner.py         Top-down refinement pass
    │
    │   ── rename application ────────────────────────────────────────
    ├── renamer.py         Rename policy + idc.set_name wrapper
    │
    │   ── persistence ────────────────────────────────────────────────
    ├── audit.py           Append-only JSONL audit log
    ├── llm_log.py         Aggregated verbatim LLM-response JSON log
    ├── export.py          Review JSON writer (one-way view of the KB)
    │
    │   ── macro reports (§17) ───────────────────────────────────────
    ├── report.py           Capability + diff-summary synthesis reports
    │
    │   ── cross-binary diff (§16) ───────────────────────────────────
    ├── autopair.py        Pairing, classification, relatedness -- no LLM, reads
    │                      two cached call graphs only
    └── diff.py            Old-vs-patched compare / new-removed summarize prompts,
                           num_ctx sizing + retry-on-truncation, self-consistency

tools/
└── winbindex_fetch.py    Pull real Windows binaries from WinBinDex (§16.7) --
                          standalone, stdlib only, not part of llm_renamer

tests/
├── test_diff.py           diff.py regression tests (§16.9) -- mocked LLM, no network
├── test_autopair.py       autopair.py regression tests (§16.9), incl. constant-promotion
├── test_call_graph.py     call_graph.py's _to_signed64 sign-normalization (§5.3a)
├── test_prompts.py        prompts.py's taint-signal rendering (§7.1d)
├── test_refiner.py        refiner.py's LLM-error retry + duplicate-name gate (§8.1, §8.2)
├── test_family.py         family.py's normalize/hash + KB family queries (§7.1e)
└── test_report.py         report.py's prompt construction + diff-entry filtering (§17)
```

Removed in the simplification pass: `checkpoint.py` (the KB tracks progress),
`review.py` (replaced by the one-way `export.py`), and `query.py` (folded into
`research_wingman.py ask`).

---

## 3a. State Model

All state for a database lives in `<database>.wingman/`, resolved by
`workspace.Workspace` (`llm_responses.json` included as of 2026-08-15 — it
used to sit beside the database file itself for at-a-glance visibility, but
that traded away consistency with everything else for a marginal UX win and
was moved in). Nothing reads or writes the current working directory.
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

### The name authority — resolved at point of use, never from a shadow

The KB is the source of truth for the *analysis* (proposal, verdict, applied
flag), but it is **not** the authority for a function's *current name*. That is
owned by the **i64**, deliberately: `analyze` never writes names (invariant 9),
and an analyst's rename in IDA must win. The KB's `old_name`/`applied_name` and
the cached graph's node names are **historical shadows** — snapshots taken when
we analyzed or applied — and drift the moment anything renames. They exist for
provenance, never to answer "what is this function called *now*".

So "the current name" is resolved from exactly one authority at the point of use:

- **IDA open** (analyze/apply): `FunctionContextExtractor.current_name(ea)`
  (live `idc.get_func_name`) is the authority. Prompt building
  (`ctx["callee_addr_names"]`), the callee-name substitution (§7.1c), and
  `apply`'s write-time re-check all resolve through it — none read a KB shadow
  as "current". This is what closed the name-sync hole at its root: the body
  token to rewrite is taken from the live callee name, not a guessed shadow.
- **IDA closed** (map/ask): the cached graph name is used as an *explicit stale
  proxy*, reconciled against the KB (`navigate.resolve_one` KB fallback,
  `mapview` KB cross-ref) and kept fresh by `apply`'s `update_cached_names`
  patch (§5.6). It is treated as possibly-stale by construction, never trusted
  as ground truth.

The rule that prevents this whole class of drift bug: **never read a stored
name field as the current name — resolve it.**

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
| `-f NAME...` | `full_subtree()` per target, forced re-analysis | varies |
| `--top N` | `top_scored()` + `unnamed_only()` + `full_subtree()` | varies |
| `--all` | every auto-named function | thousands |

Three path-shaped scope selectors (`--callers NAME` → `ancestors()`,
`--between A B` → `paths_between()` + `full_subtree()`, `--to-sinks [N]` →
`paths_to_sinks(limit=N)` + `full_subtree()`) were cut 2026-08-19 as part of a
CLI-bloat pass: each was real, but never used in practice, and each was
strictly "look, then spend" split across one flag instead of two commands --
`map --paths`/`--explore`/`--find` already do the free looking, `-f` already
does the paid spending. `navigate.ancestors()` and `navigate.paths_between()`
were deleted along with them (confirmed genuinely dead — single call site
each); `paths_to_sinks()` stays, since `map --paths` still uses it.

`Plan` carries the scope size, how many are already analyzed (and therefore
skipped), and the resulting LLM-call count. `Plan.estimate()` multiplies that
by the measured `seconds_per_call`. `analyze(confirm=...)` hands the plan to
the caller — the CLI's cost-confirmation prompt — before anything is spent. This is what
makes it safe for scope expansion to be unbounded (see below) rather than
capped: the cost is always quoted and confirmable before it's spent, so an
unexpectedly large subtree is surfaced as a bigger number to approve, never
silently spent.

`map --paths`' own path-finding (still live, via `paths_to_sinks`) is bounded
on purpose (`max_paths`, `max_depth` in `shortest_path`): a dense call graph
has effectively unlimited distinct paths, and an unbounded search would hang
rather than return a useful selection.

### `navigate.full_subtree()` — the standard scope-expansion pattern

`-f` and `--top N` expand their selection through the same function:
`navigate.full_subtree(graph, addrs)` returns each address plus its complete
callee subtree, walked all the way to true leaves (`descendants(depth=None)`),
not just one hop. This is deliberate and uniform, not scope-specific tuning:

- `--top N` picks by score across the whole graph with no regard for whether
  a picked function's neighbours are also picked, so it routinely landed
  functions in total isolation — no analyzed caller or callee anywhere in
  the prompt, nothing but the function's own body to reason from.
- The now-removed path-shaped scopes (`--between`/`--to-sinks`, see §3b's
  scope table) had the same problem in their day: `paths_between`/
  `paths_to_sinks` each print (and originally selected) a *single* shortest
  path per source/sink pair — a path node's other real callees, not on that
  printed chain, were otherwise silently excluded from the scope, leaving
  bottom-up context injection incomplete. `full_subtree()` fixed that for as
  long as those scopes existed; the lesson (never hand the LLM a target
  without its real dependencies also in scope) is why `-f`/`--top N` still
  route through the same function today.
- An earlier version of this fix (`with_immediate_callees()`, since removed)
  only expanded one hop, reasoning that a bounded path scope shouldn't become
  an unbounded subtree walk. In practice one hop wasn't enough — real
  functions are called through several layers of unnamed `sub_*` glue before
  reaching anything substantive, so a one-hop cap still left most of the
  actual dependency chain unsummarized. `full_subtree()` walks the whole way
  down instead, and relies on the cost quote (`Plan.estimate()`, above) as
  the safety valve for scope size rather than an artificial depth cap.

There is deliberately no *downward* radius selector on the CLI. An earlier
`--near NAME --direction {down,up,both} --depth N` offered one, but its default
(`down`) was just a depth-capped `-f`: both select a function plus what it
calls, and `-f` does it completely via `full_subtree()`. Two ways to say the
same thing is how a CLI teaches its user the wrong model, and the cost quote —
not a depth cap — is already the safety valve for scope size. `--callers
NAME` (fixed 2 hops, `ancestors()`) covered the *upward* case this same way
for a while, but was itself cut 2026-08-19 — real and non-duplicative, but
confirmed unused across an entire extended real session, the same "never
actually reached for it" bar `--between`/`--to-sinks` were cut against.
(`navigate.near()`, which implemented all three directions for the
interactive menu's free-browsing case, was removed earlier along with
`menu.py`.)

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
  + low_complexity_bonus            # +2  if cyclomatic_complexity(f) ≤ 5
  + high_complexity_bonus           # +3  if cc ≥ 20 AND caller_count ≤ 3 (elif,
                                     #     mutually exclusive with the low branch)
  + xref_focus_score(f)             # signed weight — the elite filtering lens
```

**Cyclomatic complexity** is approximated as `max(0, basic_block_count - 1)`.
Low complexity → straightforward code → higher LLM confidence → better callee
summaries for callers.

**`high_complexity_bonus` (added 2026-08-13)** exists because the formula
above it had a real, live-confirmed blind spot: complexity only ever added
score for *small* functions, so a large function had nothing but
`xref_focus_score` to compete with a tiny wrapper at the same caller count —
and a genuine entry point reached only through indirect dispatch (0-3 direct
callers is exactly `xref_focus_score`'s top bracket) looks, by caller count
alone, identical to a trivial one-block syscall-status wrapper that also
happens to have few callers. Confirmed on a real statically-linked MIPS
malware sample: the actual C2-setup function (57 basic blocks, 0 direct
callers) scored 4.0 under the old formula — tied with a shared syscall-wrapper
utility called from just 2-3 places — and never surfaced in `--suspicious`'s
top 25 at all. Under the new formula it scores 7.0, above the noise cluster's
6.0, and is the second entry point listed in the raw `map` overview.
Deliberately `elif`, not additive with the low-complexity branch (a function
is either small or large, never both), and deliberately gated on *both* size
and low caller count — size alone would also promote a large, heavily-called
function (a bundled `vfprintf` implementation, say), which is exactly the
shared-utility case `xref_focus_score` already exists to deprioritize; the
two conditions have to agree, not just one of them.

**`sink_bonus`/`input_reachable_bonus` are import-name-driven** (`call_graph.py`'s
`dangerous_sinks`/`input_sink_apis` match against `import_refs`) and
structurally cannot fire on a statically-linked binary with no import table —
confirmed on the same sample: 0 sinks, 0 input-reachable, despite the binary
visibly touching memory and network input throughout its decompiled code.
Not fixed here — recognizing sinks from raw syscall numbers instead of
import names would need per-architecture instruction decoding, and a first
look at this sample found raw syscalls aren't even a clean signal on their
own (the errno/status-wrapper noise cluster uses them exactly as much as the
real logic does). `mapview.overview()` now prints an explicit note when a
graph shows zero sinks *and* zero input-reachable functions *and* zero
imports at all, so `0`/`0` reads as "undetectable on this binary shape," not
"nothing dangerous here."

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
    constant_operands: list[int] = field(default_factory=list)  # see §5.3a

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
   - Constant operands: `o_imm` operands at each instruction, filtered — see §5.3a
3. `_annotate_caller_counts` — increment `caller_count` from edges
4. `_annotate_callee_lists` — populate `callee_addresses` from edges
5. `_annotate_basic_blocks` — `ida_gdl.FlowChart(func)` per function
6. `_annotate_input_reachable` — DFS forward from input-API seed functions

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

### 5.3a Constant-operand extraction (`_extract_constants`, added 2026-08-11)

Real motivation: `autopair.classify` (§16.2) treated identical `size_bytes` +
`basic_block_count` as a hard guarantee of "unchanged" — but many x86-64
immediate encodings are fixed-width regardless of value, so a changed buffer
size / threshold / bitmask can leave both untouched. Real example from this
session's own crypt32.dll validation: `InitCmsRecipientEncodeInfo`'s
allocation math changed from `352 * a2` to `a2 << 9` (512 * a2) with zero
structural change. `constant_operands` closes that gap: it feeds
`autopair.classify`'s promotion of otherwise-`unchanged` pairs to `candidate`.

For each instruction, each `o_imm` operand is kept unless: (a) `ida_bytes.
is_off(flags, n)` — IDA has already resolved it to a symbolic address/offset
reference (`mov rax, offset g_Global`); these trivially differ across any two
builds via relocation/section-layout, not a logic change, or (b) its
magnitude is `<= _CONST_MIN_ABS` (16) — near-universal small values (loop
increments, null checks) that would swamp the signal. Values are normalized
via `_to_signed64` before the magnitude check: `idc.get_operand_value`
doesn't consistently sign-extend, so a small negative immediate like -1 or
-512 in a 64-bit-mode instruction can come back as the raw unsigned 64-bit
encoding (18446744073709551615, 18446744073709551104) — without normalizing
first, those slipped straight past the magnitude filter as if they were huge,
meaningful constants (confirmed live against real clfs.sys functions). The
per-function set is sorted, deduped, and capped at 64 for a bounded field.

**Real values observed** (clfs.sys, live-verified): NTSTATUS codes
(`-1073741790` = `0xC0000022`), struct/allocation sizes (`32, 48, 96, 200`),
CLFS magic signatures (`0x436c667070666c43` = `"ClfpfppfC"`), and known
compiler-generated constants (`memset`'s byte-broadcast multiplier
`0x101010101010101`, the divide-by-3 reciprocal `0xaaaaaaaaaaaaaaab`).

**Known false-positive source, verified self-correcting, not fixed further:**
WPP trace-message IDs are literal immediates too (auto-generated per call
site, shift whenever any earlier source line changes) and pass the filter
since they aren't address-like. On clfs.sys, 32 of 1292 previously-`unchanged`
pairs were promoted this way (2.5%) — live-tested against 2 of them: the LLM
correctly recognized both as WPP trace-GUID/line-number churn, explicitly
naming it as such and returning `[NO DIFF]`/low-risk rather than being fooled
into a false security story. Cost is one bounded, cheap LLM call per
promotion, same class of self-correction the tool already relies on for other
cosmetic-only cases (e.g. `wil_InitializeFeatureStaging`'s decompiler
artifact, §16.4).

**Promotion rate is highly binary-specific, not a fixed overhead — measured
across three real WinBinDex pairs (2026-08-11):**

| Binary | Previously-`unchanged` promoted | Rate |
|---|---|---|
| clfs.sys | 32 / 1292 | 2.5% |
| http.sys | 0 / 3881 | 0% |
| ntfs.sys | 114 / 2951 | **~3.9% of pairs, but 114 of 120 (95%) of ALL candidates** |

http.sys shows zero promotions — clean. ntfs.sys is the outlier: sampled
several of its 114 promoted pairs directly and found the same shape every
time — small, tightly-clustered numeric IDs with tiny deltas (e.g.
`1208626` → `1208642`, delta 16; `2298597` → `2298596`, delta -1), the same
auto-generated-ID-churn signature as clfs.sys's WPP finding, just far more
prevalent. Consistent with ntfs.sys's own diff output elsewhere in this
session independently showing recurring `Microsoft_Windows_NtfsLog_...`
ETW-bitmask-identifier churn as a known cosmetic-only difference — this
binary appears to embed far more build-varying trace/logging identifiers per
function than clfs.sys or http.sys do. Not fixed further: the false positives
are still individually cheap and self-correcting (confirmed on clfs.sys), and
a value-shape heuristic (e.g. "small-delta pairs are probably ID churn") risks
suppressing a genuine off-by-one threshold fix, which would trade a bounded,
visible LLM-call cost for a silent false negative — a worse failure mode.
Flagged as a real, binary-dependent cost tradeoff for whoever runs `diff
--auto` against a heavily-ETW-instrumented target to weigh, not treated as a
defect requiring a code fix.

### 5.4 `input_reachable` — definition and traversal direction

Seed functions = functions that directly call any name from `input_sink_apis`
(`recv`, `read`, `fgets`, `fread`, `WSARecv`, `ReadFile`, `getchar`, `scanf`, `fscanf`).
Detected inline during `_single_pass`, before `node.import_refs` gets capped
(`max_import_refs_per_node`) -- same treatment as `dangerous_sink_calls` --
so a function with more than the cap's worth of distinct imports can't
silently lose its seed status just because the real input API landed past
the cutoff in address order (confirmed real 2026-08-16).

Traversal direction: **forward (callee direction)** from seeds, DFS
(`queue.pop()`, LIFO -- order doesn't affect the result, since this only
sets a boolean per node). A function is marked `input_reachable=true` if
it is reachable by following call edges starting from a seed. This marks
all functions in the input-processing call tree.

Overapproximation (false positives) is acceptable. This is a scoring signal, not
a security verdict.

### 5.5 Cache

The graph is serialised to JSON via `graph.save(path)` (atomic `.tmp` swap).
`load_or_build(extractor, config, cache_path, force_rebuild=False)` loads from
cache if present; rebuilds and re-saves if not. Pass `force_rebuild=True` —
what `research_wingman.py map <db> --build` does — to discard the cache. (`analyze` has no
rebuild flag of its own; it would have been a second spelling of `map --build`.)

`update_cached_names(cache_path, {ea: name})` patches node names in place
without a rebuild — called by `apply()` so the cache stays consistent with
renames written to the database (see §5.6). A rename never touches graph
*structure* (edges, sinks, bb counts), only names, so a targeted name patch is
exact and far cheaper than a full rebuild. Best-effort: any failure leaves the
cache as-was, which is merely stale, never wrong.

JSON format:
```json
{
  "nodes": { "4198400": { "address": 4198400, "name": "sub_401000", ... } },
  "edges": [[4198400, 4199000], ...]
}
```

Note: JSON object keys are strings (required by JSON spec), so addresses appear
as decimal strings in the file but are stored as integers in memory.

### 5.6 Cache staleness — name staleness vs structure staleness

Two distinct cache-staleness concerns, handled separately:

**Name staleness (common, from our own renames).** `apply()` writes renames
into the IDA database; the cached graph still holds the pre-rename `sub_*`
names. This is now closed on three layers:

- **Source fix:** `apply()` calls `update_cached_names()` for every rename it
  writes, so the cache is kept correct for applied renames without a rebuild.
  This is the primary fix — it makes *every* cache reader correct at once:
  `--find` (search by new name now hits), the `unnamed_only` filter behind
  `--suspicious`/`--top` (renamed functions correctly drop out), and every
  map view.
- **Display reconciliation:** `mapview` still cross-references the KB
  (`_kb_map`) and shows the current name + `[SEC]` marker on the primary
  line via `navigate.describe(..., name_override=...)`. This additionally
  covers the transient *analyzed-but-not-yet-applied* window, where the KB
  has a proposed name the cache patch hasn't been triggered for yet.
- **Resolution fallback:** `navigate.resolve_one()` falls through to
  `_resolve_via_kb()` (KB `new_name` lookup) when a graph name lookup misses.

**Structure staleness (rare, binary re-analyzed externally).** If functions
are added/removed in IDA after the graph was built, cached *structure* (edges,
sinks, bb counts) is stale — and a rename-only `apply` must NOT be mistaken for
this (which is why an mtime check is unsuitable: `apply` bumps the `.i64`
mtime, and `update_cached_names` bumps the cache mtime, neither reflecting a
structural change). Instead, `resolve_graph()` does a cheap function-count
comparison whenever IDA is already open (the analyze path): live
`extractor.get_function_count()` vs `len(graph.nodes)`, and prints a
non-fatal NOTE suggesting `research_wingman.py map <db> --build` if they differ. It never
auto-rebuilds (that needs IDA + minutes; the user decides).

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
| `_callee_addr_names(ea)` / `_caller_addr_names(ea)` | `idautils.FuncItems()`, `idautils.XrefsFrom/To()`, `_display_name()` |
| `sink_argument_taint(ea, sink_names)` | `ida_hexrays.decompile(ea)` → ctree walk (§7.1d) |
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

When the call graph is available, `-f` resolves
each target through `navigate.resolve_one` and expands it via
`navigate.descendants(graph, addr, depth=None)` -- the full callee subtree,
not just the named target -- so it is analyzed leaves-first with real callee
summaries in context, via `build_plan`'s `force` set (the named targets are
always re-analyzed; pulled-in callees still skip if already analyzed). With
no cached graph, `-f` analyzes exactly the named functions with no expansion,
which is what keeps it usable without paying for a whole-program graph build.

### 6.4 Rename application and IDA annotation

```python
idc.set_name(ea, new_name, idc.SN_NOCHECK)                       # rename
idc.set_func_cmt(ea, format_comment(summary, confidence), 1)     # repeatable comment (visible in callers)
```

`format_comment` (in `renamer.py`) appends the KB's confidence score to the
summary, e.g. `"Does X. (confidence score: 0.80)"`, so it's visible in IDA
without opening the KB. `SN_NOCHECK` skips IDA's name-validity check (the
validator in `validator.py` already enforces snake_case rules). Both calls
happen inside `RenamePolicy.apply_rename()`, reached only from
`pipeline.apply()` — never during analysis. The comment is written when the
KB row carries a summary. Changes are flushed to disk by
`idapro.close_database()`.

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
5. Neighbour inject  — kb.get_callee_summaries(graph.callees_of(ea))
                       kb.get_callers_in_kb(addr, graph.callers_of(ea))
6. Build prompt      — build_user_prompt(ctx, callee_kb_entries, caller_kb_entries)
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

### 7.1a Embedded method-name strings (WPP trace names)

`prompts.method_name_strings()` scans a function's referenced strings for
demangled C++ qualified names (`Class::Method`, matched strictly by
`_METHOD_NAME_RE`). Windows components built with WPP software tracing embed
each function's own fully-qualified name as a literal trace string, so this is
a near-ground-truth naming signal already present in the binary — on the real
`clfs_old` sample, 75 of 840 unnamed functions (~9%) carry one.

`build_user_prompt` elevates these above the generic "Referenced strings"
list into their own section (and removes them from the generic list to avoid
showing the same string twice, the same dedup discipline used for callee
names), and `SYSTEM_PROMPT` instructs the model to treat the section as the
strongest available signal and base the name on it unless the pseudocode
clearly contradicts it. It is a *hint, not a hard rename*: a function can
reference several method-name strings (its own plus ones it logs for callees),
and overload/thunk variants share one string, so the model reconciles the hint
against the code rather than the tool renaming blindly. Measured effect on a
fresh function: `CClfsLogFcbPhysical::FlushMetadata` → `flush_metadata` at
confidence 1.00, with a class-aware summary — versus the 0.75–0.90 typical for
comparable functions lacking the string.

Because a WPP name is the strongest signal, it must never be lost to the generic
string cap: `_strings` scans up to `scan_cap` referenced strings and keeps *every*
`::`-bearing one before capping the generic remainder, so a method-name string
past position 12 in address order still reaches `method_name_strings` (a plain
first-12 slice previously dropped it). No measured impact on `clfs_old` — no
function there references a method-name string past position 12 — but a latent
correctness hole on binaries whose functions reference more strings.

### 7.1b Constant decoding and IDA type signature

Two further deterministic prompt enrichments, both zero-LLM-cost:

- **`prompts.annotate_constants()`** rewrites the pseudocode before it enters
  the prompt, appending `/* ... */` hints to two classes of developer-authored
  magic number the decompiler renders opaquely:
  - **Pool tags** — an 8-hex-digit constant whose 4 little-endian bytes are
    printable and mostly alphanumeric is decoded to its ASCII
    (`0x73666C43u` → `/* 'Clfs' */`), naming the *purpose* of an allocation.
  - **NTSTATUS codes** — known values from a small table become symbolic
    (`3221225485LL` → `/* STATUS_INVALID_PARAMETER */`); unknown but
    well-formed codes with a small non-zero facility become a factual
    `/* NTSTATUS error (facility 0xNN, code 0xNNNN) */`. The facility bound
    (`< 0x100`) and `code != 0` keep bit-masks like `0xFFFFFFFE` out.

  This was worth doing deterministically because the model decoded these
  *inconsistently and sometimes wrongly* on its own — it was observed
  miscalculating a driver status code's facility as `0x22` when it is
  actually `0x1A`. Measured effect: re-analyzing `attach_clfs_managed_log_client`
  with the pool tags decoded (`'ClMq'`/`'ClMx'` tracking allocations) raised
  confidence 0.85 → 0.95 with a stable name.

- **IDA type signature** (`FunctionContextExtractor._type_signature`,
  `idc.get_type`) is surfaced as a separate `IDA type` prompt line, but only
  when it differs from the decompiler's first-line prototype — for plain
  `sub_` functions the two usually match and it's suppressed; it earns its
  place on library-recognised or analyst-typed functions where IDA carries a
  richer signature (named kernel types like `PIRP`/`PFILE_OBJECT`).

### 7.1c Inline callee-name substitution (name-sync)

`analyze` never renames the database (invariant 9), so the decompiled body
always shows callees under their *current* DB name — a raw `sub_...` on a fresh
run, or a stale `maybe_...`. Callee summaries, however, are injected keyed by
the proposed `new_name`. Left as-is the model cannot map a summary to the call
it describes: measured at **~85% of visible callee summaries stranded** on a
fresh bottom-up run (23% even in a mature applied KB, from re-analysis drift).

`prompts.substitute_callee_names(pseudocode, callee_kb_entries, callee_addr_names)`
closes this, called inside `build_user_prompt` just before `annotate_constants`.
It rewrites the body so analyzed callees read under their proposed name
(`v6 = compute_crc_checksum_loop(...)` instead of `v6 = sub_1C0006E80(...)`).
The body token to replace is the callee's **live** name, resolved by address via
`callee_addr_names` (the single live-name authority, §3a); the KB shadows
`old_name`/`applied_name` are a fallback only when a callee isn't in that map.
Whole-word only, approved callees only, and — critically — only
*raw/placeholder* tokens are rewritten (`_REPLACEABLE_PREFIXES`:
`sub_`/`nullsub_`/`j_`/`locret_`/`loc_`/`unknown_libname`/`maybe_`). An
already-applied descriptive name is left intact, so a collision-disambiguated
`get_control_record_4` (whose KB `new_name` is the base `get_control_record`) is
*not* rewritten — otherwise three distinct callees would collapse to one name in
the body.

**The listing must agree with the body.** Not rewriting suffixed names is
correct, but it reopened the same hole from the other side: the neighbour
listing labelled each callee with its raw KB `new_name`, so a callee applied as
`wrapper_identity_10` was *listed* as `wrapper_identity` — a name appearing
nowhere in the code. Measured at **64 of 355 functions (18%)** carrying at least
one stranded summary. Fixed by deriving both from one map:
`prompts.name_substitutions()` is the single definition of which neighbours are
shown under their proposed name versus their live one, and
`prompts.display_name_for()` computes the listing label *from that same map*, so
the two cannot drift apart. `_render_kb_neighbours` takes the address→live-name
map for callees (`ctx["callee_addr_names"]`) and callers
(`ctx["caller_addr_names"]`) alike. Note this only bites *after* an apply — a
fresh run has placeholder body tokens that get rewritten normally.

**Symbol-named neighbours must be demangled to agree with the body, too.** The
name-sync story above covers `sub_`/placeholder callees. On a symbol-bearing
binary (PDB/exports, like the CLFS driver) the *other* half appears: a named
neighbour's authority name is the raw MSVC mangle
(`?Initialize@CClfsManagedLogClient@@UEAA...`), but Hex-Rays prints the
demangled `Class::Method` form in the body — so listing the neighbour under the
mangle both injects encoded noise and strands its summary (the model can't tie a
summary filed under the mangle to the demangled call it reads). `_display_name`
(used by `_callee_addr_names`/`_caller_addr_names`) demangles to the body's short
form via `ida_name.get_short_name`, dropping the trailing parameter list the body
omits at the call site. Display-only: `current_name` (the rename authority, §3a)
stays raw, and non-mangled names (`sub_`, analyst, applied) pass through
untouched, so callee-substitution is unaffected.

### 7.1d Deterministic call-graph signals

The Phase-1 graph already computes, per node, which memory/allocation sinks a
function calls (`dangerous_sink_calls`, complete and uncapped) and whether it is
`input_reachable` — the tool's core triage facts. `pipeline._run_plan` folds
these plus `caller_count` into the ctx, and `prompts._render_graph_signals`
renders a short **Call-graph signals (deterministic, precomputed)** section:
sinks called (the security_relevant/risk judgement previously re-derived this
from pseudocode, and the *raw import list is capped at 15 in address order* so a
sink could fall off the prompt entirely while the graph still had it flagged),
input-reachability, and caller count (utility-vs-unique, with `caller_count==0`
doubling as the honest "reached only via indirect/vtable dispatch, no caller
context" signal). Rendered as facts, not conclusions; the section is omitted
entirely when there is nothing to say (no filler). Measured honestly on
`clfs_old` by **name/summary correctness, not confidence** (which is measured not
to predict correctness, §sauce): an 18-function old-vs-new A/B changed the
produced *name* in only 1 case and reworded ~8 summaries cosmetically, **zero
regressions**. So these signals are deterministic-coverage insurance (a sink or
signal that would otherwise fall off a capped list, a vtable fact the graph can't
see), not a naming-quality boost on a symbol-rich corpus where the body already
resolves most names — their payoff is on truncated/symbol-less cases this corpus
doesn't exercise. The same two security signals (sinks, input-reachability) are
also carried into the refiner prompt (`refiner._build_prompt`), so a top-down
pass re-emitting `security_relevant` weighs them rather than losing them.

**Indirect/vtable reachability** (`FunctionContextExtractor._indirect_refs`) is
the same section's answer to the call graph's biggest blind spot: it follows
only direct code xrefs, so virtual methods, registered callbacks and
dispatch-table entries have zero callers and no caller context. On `clfs_old`
that is **300 of 323 `caller_count==0` functions** (262 still `sub_`) — without a
signal the prompt just says "no callers" and the model can't tell an entry point
from a vtable slot. The deterministic tell is a **data** xref to the entry from a
*non-unwind* section: `.pdata`/`.xdata` reference every function's entry (unwind
info) and are excluded, but a `.rdata`/`.data` vtable slot or a `.text` offset
means the function is reached through a pointer. This is computed in the extractor
(not the graph): it needs only `XrefsTo(ea)`, stays fresh with no cache rebuild,
and works even on a targeted run with no graph. When the referrer is `.text` code
inside another function that function is named (demangled) — the one indirect
relationship resolvable for free, e.g. `CsqAcquireLock` shown as registered in
`CClfsLogFcbPhysical::CClfsLogFcbPhysical`, or an async-completion routine in
`...::FlushLog`. `.rdata` vtable slots set only the boolean; they are deliberately
*not* walked back to a constructor (measured unreliable — it would fabricate a
caller). A/B isolating just this signal on 7 `sub_` vtable functions: **no name
changes, no regressions** (its value is the categorical fix — 300 misleading "no
callers" lines corrected — not a per-function naming change).

**Parameter-to-sink taint** (`FunctionContextExtractor.sink_argument_taint`,
added 2026-08-11) is real dataflow layered on top of the sink listing above,
which only ever meant "this function calls something dangerous somewhere" —
zero awareness of which argument, or whether the call even touches
attacker-influenced data. `pipeline._run_plan` calls it only for the subset
already flagged by `dangerous_sink_calls` (bounded cost: not every function,
and Hex-Rays caches per-ea within a session so this is normally a cache hit,
not a second full decompile). Walks the ctree of ONE already-known sink call:
for each argument expression, recursively checks whether a `cot_var` node
resolves to an `lvar_t` with `is_arg_var` true — directly or through simple
arithmetic/derefs/casts. Renders as a materially stronger line than the plain
sink listing: *"ProbeForWrite's argument #1, #2 traced (via decompiler
dataflow, not a guess) to this function's own input parameter."*

Two real implementation bugs caught only by live testing against real
functions (mocks can't fake a `cfunc_t`): `idc.is_off` doesn't exist on this
IDA version (`ida_bytes.is_off` is correct — same fix needed in §5.3a's
constant extraction, found in the same session), and `lvar_t.is_arg_var` is a
boolean **attribute**, not a method — calling it as `is_arg_var()` raised
`TypeError`, which an overly broad `try/except: return []` around the whole
ctree walk silently swallowed as a false "no taint found" instead of a
visible failure. Fixed by narrowing the try/except to only the decompile call
itself (which can legitimately fail for some functions) and letting a real
traversal bug surface — it now relies on `pipeline._run_plan`'s existing
per-function exception boundary (same one `extract()` already uses) rather
than a second, silently-swallowing layer.

**Validated live** against real clfs.sys functions, not just unit tests
(this method has none — it's fundamentally untestable without a real
`cfunc_t`; `tests/test_prompts.py` covers the rendering side instead):
`ClfsProbeAndAllocateMdl`'s `ProbeForWrite(a2, a3, 8u)` correctly tainted
args 1–2 (`a2`, `a3`, both parameters) and correctly excluded arg 3 (the
constant `8u`) — the exact address/length-validation pattern that was
security-relevant in `NtfsWriteRawEncrypted` earlier this session. Broad
smoke test across all 176 real functions in the binary with a sink call:
**0 errors, 42 (24%) with at least one genuine tainted finding.** Full
pipeline wiring (extract → graph lookup → taint → prompt) confirmed by
dumping the actual rendered prompt text, not just the intermediate dict.

**Honest scope limitation:** this is single-function-local syntactic tracing,
not interprocedural dataflow. `this->field` used as a sink argument counts as
"parameter-derived" (the base object IS a parameter), even when the field
holds an internal constant set by a constructor rather than genuinely
external input — a real precision ceiling, not a bug. Still strictly more
information than the graph-only `input_reachable` heuristic it sits beside,
which has no argument- or dataflow-awareness at all (see §15).

**End-to-end confirmation, not just prompt-text verification (2026-08-11):**
ran a real `research_wingman.py analyze -f ClfsProbeAndAllocateMdl --no-apply`
(the same function used to validate the raw method above) to confirm the LLM
actually *uses* the signal, not just that it's rendered correctly. Result:
`risk=high`, `security-relevant`, name `clfs_probe_and_allocate_mdl`, summary
"Performs ProbeForWrite on **user-controlled address and size**" — language
mirroring the taint line's own framing ("treat as attacker-influenced"),
not something derivable from the bare `ProbeForWrite` call in isolation
without knowing which specific arguments trace to the function's own input.

### 7.1e Prompt-content caps: no silent truncation, no cap on real neighbours

Every place a per-function prompt drops content past some length was, until
2026-08-16, a bare hardcoded number with no truncation marker shown to the
model — the prompt just quietly got shorter, and nothing about the model's
output signaled that anything was missing. Confirmed as a real (not
theoretical) problem on the `3b8e...` malware sample: a 64-callee
orchestrator/dispatcher function has a genuine 722-line decompiled body, but
`FunctionContextExtractor._pseudocode` capped it at
`analysis.max_pseudocode_lines` = **200** — cutting 522 lines (72%) and, with
them, 22 of the function's 39 real callee names from the prompt entirely (not
in the body text *or* the neighbour-summary section, since both draw on the
same truncated view). The model's analysis of that function never mentioned
the PEB `NtGlobalFlag` check, the `__rdtsc()` timing probe, or the
`Ldr->InMemoryOrderModuleList` walk it actually performs — all past line 200.

Two fixes, both now live:

1. **Every prompt-content cap is a named `analysis`/`graph` config key**, not
   a bare literal buried in the function that happens to use it (`config.py`'s
   `_TUNING_DEFAULTS`, overridable in `config.json` — see §11's full table).
   `max_pseudocode_lines` is raised to **1000** in the shipped `config.json`
   (`analyze_sized`'s existing `num_ctx` auto-sizing and retry-on-truncation,
   §16.4, already handle a larger real prompt — the cost is a bigger/slower
   call, not a correctness risk, confirmed live: the 722-line function's full
   prompt ran at `num_ctx=16384`, ~70s, no truncation).

2. **Direct-child/caller summaries are never capped**, by explicit design
   choice — reverting an earlier cap-at-5 that was tried the same day. Every
   callee/caller with a real KB entry gets its full summary shown in
   `_render_kb_neighbours` unconditionally, still ordered security-relevant-
   then-confidence-first (`KnowledgeBase._by_addresses`'s
   `ORDER BY security_relevant DESC, confidence DESC`) so a long listing still
   reads most-important-first. Verified: the 64-callee case above went from
   200-line body / 5-of-39 callee summaries → full 722-line body / all 39
   summaries, 33KB prompt, still one `num_ctx=16384` call, and the resulting
   analysis correctly attributed every evasion behavior found in the fuller
   read. The **only** thing still capped is the bare-name tail in the same
   function — neighbours with *no* KB entry yet, which carry no content
   beyond "not yet analyzed" (`analysis.max_unanalyzed_neighbours_shown`,
   default 5); a long list of those really is filler, unlike a real summary.

3. **`pseudocode_truncated` makes a still-possible truncation visible to the
   operator, not just the model.** Raising the default to 1000 lines doesn't
   remove the cap — a function with a real body longer than
   `max_pseudocode_lines` still gets cut, and until 2026-08-16 that fact was
   only ever visible *inside* the prompt text itself (`_trim_lines`'s
   `"// ... [N more lines truncated]"` marker), with nothing surfaced to
   whoever's running the tool. `FunctionContextExtractor.extract()` now
   detects that marker and returns `pseudocode_truncated: bool`; `pipeline.py`
   prints a `[WARNING]` on the affected function immediately (naming the
   config key to raise) and `_print_analyze_summary`/`ask.status` both flag
   the running total; `KnowledgeBase` persists the flag per function
   (migration-safe `pseudocode_truncated INTEGER DEFAULT 0` column) and
   exposes `get_pseudocode_truncated()` to list every affected function after
   the fact, address by address, so raising the cap and re-running
   `--redo -f` on exactly those is a targeted fix, not a guess.

Scope was never the issue and is unchanged by either fix: `callees_of`/
`callers_of` (`call_graph.py`) are one-hop edge lookups built from a single
pass over each function's own call instructions — there is no transitive/
grandchild walk anywhere in the call graph. "Every direct child" has always
meant exactly that.

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
  "interesting_behaviors": ["observation 1", "observation 2"]
}
```

`risk` is a severity axis independent of `confidence`: confidence is how sure
the model is, risk is how costly a wrong answer would be. `skip_high_risk`
(default on) rejects `risk="high"` only when confidence is *also* below
`high_risk_confidence_override` (default 0.8) — at or above it, the rename is
approved and `risk="high"` stays recorded in the KB, just not auto-rejected.
This was a deliberate refinement: blanket-rejecting every high-risk result
regardless of confidence turned out to block genuinely correct, well-evidenced
renames on real security-sensitive code (e.g. `SeAccessCheck`/
`SeAppendPrivileges` access-check logic) purely because the code itself is
dangerous, not because the model's answer was actually wrong. See
`validator.py`, step 4b.

### 7.5 Audit trail vs. knowledge base vs. raw LLM log

Three files can look like they're recording the same thing (address, name,
confidence, risk, some kind of reason) and it's a fair question why all
three exist. They differ on what's current vs. historical, and validated vs.
raw -- not by accident, but each was genuinely motivated by a different
need:

- **`knowledge_base.sqlite` is current state.** One row per address,
  overwritten on redo/re-analysis. The only file `apply`/`ask`/resume logic
  ever reads.
- **`llm_responses.json` is the raw, unvalidated model I/O, across every
  call ever made.** Rewritten as a whole array per call (not appended), but
  never truncates history -- a re-analyzed function's earlier raw replies
  stay in the array alongside the new one. The only file that captures both
  the `analyze` *and* `refine` phases (`phase` field), and the only one with
  the model's answer *before* `validator.py` sanitizes/rejects it.
- **`audit.jsonl` is a permanent, append-only timeline of decisions**, not a
  third copy of the analysis. It originally duplicated confidence/risk/reason
  wholesale from the KB -- removed 2026-08-15, since that data already lives
  in the KB (current) and `llm_responses.json` (full history, raw). What it
  uniquely provides: one line per *action* (an analyze decision, or an apply
  attempt), tagged `phase: "analyze"|"apply"` and `status` (mirroring
  `_apply_one()`'s own return vocabulary -- `applied`/`skip`/`fail`/`error`
  for apply, `approved`/`rejected`/`error` for analyze), so it's the one file
  that shows the full sequence of what happened across every run ever done on
  this database, not just the latest outcome.

**A real bug this split caught:** before the split, the analyze loop's own
audit record hardcoded `applied=False` unconditionally (`pipeline.py`,
now-removed) -- even on the `apply_immediately` path where `_apply_one()` had
just written `applied=True` moments earlier in its *own*, separate record for
the same address. Two lines per function, same run, contradicting each other
on the one field named `applied`. Root cause: that record was describing the
*analyze* decision, not the *apply* outcome, and never should have carried an
`applied` field at all. Fixed by giving each phase's record only the fields
that phase actually knows about -- the analyze-phase record no longer claims
anything about apply, `_apply_one()` remains the single source for that.

---

## 8. Refinement (`refiner.py`)

Two distinct mechanisms live here: `Refiner.run()` (the standard top-down pass)
and `repair_naming_conflicts()` (deterministic defect repair, §8.2). Both run
automatically at the end of a full `analyze`, in that order, gated by the same
`--no-refine` flag — `pipeline._run_plan` calls `repair_naming_conflicts`
immediately after `Refiner.run()` finishes. (`repair_naming_conflicts` was
built and validated — see §8.2's real-audit history — in an earlier session
but had no caller anywhere in the CLI/menu until 2026-08-07; found via a
`vulture` dead-code sweep, then wired in rather than deleted, since it was a
working, previously-proven mechanism, not cruft.)

### 8.1 `Refiner.run()` — top-down pass

**One pass per function. No looping.** Runs at the end of a full `analyze`,
unless `--no-refine`.

For each function in the KB where `phase3_done=1`, `phase4_refined=0`, and
`status='approved'` (a rejected row -- low confidence, `risk=high`, vague
name, ... -- is a deliberate decision; refinement only reconsiders proposals
that were actually accepted, never resurrects a rejected one behind the
policy's back):

1. **Skip** if `confidence >= refinement_confidence_skip` (code default 0.85,
   shipped in `config.json` as 0.7 — raised after a live run showed 106 of 127
   "low confidence" candidates actually sat at 0.70–0.79, the model's normal
   range rather than genuine uncertainty) — *except* `wrapper_*` entries,
   which bypass the confidence skip entirely (`kb.get_unrefined`). Their high
   confidence reflects a *structural* fact ("this body is a bare forward"),
   not semantic certainty, so they are exactly the entries worth revisiting.
   See §8.3.
2. **Skip** if no callers of this function are found in the KB.
3. Re-query the LLM with the original summary, **every** analyzed caller's
   summary and **the function's own callee summaries** (`graph.callees_of` →
   `kb.get_callee_summaries`) — uncapped, same "every direct neighbour, never
   just a sample" design as the main analyze prompt, §7.1e — and, for
   trivial-bodied functions, **real call-site lines** from each caller's
   decompiled code (`extractor.call_site_snippet`, §8.4).
4. If the response reports a change: update `new_name`, `summary`, `confidence`,
   `security_relevant`, `interesting_behaviors` in-place. "Reports a change" is
   `_response_changed()`, not the raw `changed` flag — see §8.5.
5. Set `phase4_refined=1` — **except** when the LLM call itself raised
   `LLMError` (network error, server down, timeout). That case only prints and
   `continue`s, leaving the row eligible for a future run to retry. Confirmed
   real 2026-08-19: a mid-run Ollama outage hit this exact branch and, before
   the fix, permanently dropped 57 functions from every future refine pass —
   discovered only by manually diffing the run log for "LLM error" lines and
   hand-resetting `phase4_refined=0`. The other three skip branches above
   (unparseable address, no caller yet, no change) are structural facts a
   rerun can't change, so those still mark refined — only the transient-failure
   branch was wrong.

### 8.2 `repair_naming_conflicts()` — deterministic defect repair

`Refiner.run` only writes when the model reports a change, so an entry that has
already settled into a *wrong* state gets its bad answer echoed back verbatim
forever. This pass asks a different question: not "has anything new changed?"
but "does the current answer violate a rule we can check mechanically?"

Three detectors, all gated on `_is_specific_name` so the deliberate `wrapper_*`
shared-bucket convention never trips them:

| Detector | Fires when | Certainty |
|---|---|---|
| `_detect_conflict` (collision) | `new_name` equals one of this function's own callees | always wrong |
| `_detect_conflict` (self-reference) | summary/reason describes the function forwarding to *its own* name | always wrong |
| `_detect_duplicate_name` | a specific name is shared with an unrelated (non-caller/callee) approved function | advisory — may be a legitimate duplicate-body sibling |

Matches get one forced corrective LLM call. **The pass loops** (`_repair_round`,
`repair_max_rounds` — code default 5, shipped in `config.json` as 3) re-scanning
KB state after each round's writes, because resolving one collision can rename
an entry onto a name that collides with a *third* function — which a single
pass cannot see. It stops when a round fixes nothing.

**Oscillation guard.** A separate, real failure mode from the third-party
collision above: an entry can ping-pong between the same two LLM-proposed
names forever (`atomic_compare_and_swap_ptr` ↔ `..._check_status`, confirmed
2026-08-19, twice, in consecutive runs of the same sample, still unresolved at
`max_rounds=5` both times) — the model has no memory of a name it already
proposed and reverted from earlier in the same repair call. `seen_names`
(a `dict[address, set[name]]`, local to one `repair_naming_conflicts()` call,
never persisted) tracks every name each address has carried during the call;
before writing a repair result, if the proposed name is already in that
address's set, the write is skipped and logged instead of applied. A 2-cycle
now converges in exactly 2 rounds instead of burning every remaining round on
the same flip. This also catches the noisier variant of the same root cause —
the model sometimes returns `no_change: false` while proposing the *current*
name back unchanged (`_response_changed` trusts that flag over the identical
name) — which previously logged a no-op `"repaired X -> X"` and counted as
fixed every round for nothing; now caught by the same guard on round 1, since
the current name is seeded into the set before the LLM call.

**This is deliberately targeted, never a blanket re-review.** A full
unconditional resweep of all 216 entries was tried once: it fixed one
long-standing bug and simultaneously regressed five entries that had never been
flagged. Each LLM call is an independent sample, not a monotonic improvement, so
re-querying a correct answer is pure risk. Re-review requires a concrete trigger
— new caller evidence, a detector match, or an audit finding.

### 8.3 Structural vs semantic confidence

A trivial body (`return -1;`, a bare forward) supports a *structural* claim with
total certainty and a *semantic* claim with none. Conflating them produces
confidently wrong names, so `wrapper_*` entries carry high confidence yet are
never skipped on confidence grounds.

### 8.4 Call-site evidence (`extractor.call_site_snippet`)

For a trivial body, the caller is the only real evidence. The snippet is a
lightweight **def-use slice**, not a line window: extract the argument tokens at
the call, then include only other lines sharing those operands, wherever they
sit. A fixed ±N-line window was tried first and mislead the model twice by
dragging in unrelated neighbours — an unrelated sibling call (producing a real,
applied name collision) and an unrelated local's assignment (producing a
fabricated "-1 default" claim). Hex-Rays stack/register bookkeeping comments and
the caller's own prototype line are stripped as noise.

### 8.5 Trusting the payload over the flag

`gemma4:26b` repeatedly returned `changed: false` (or `no_change: true` in the
repair schema) while filling in a `suggested_name` that genuinely differed from
the current one — reasoning correctly, labelling wrongly.
`_response_changed(raw, current_name)` therefore trusts the concrete
`suggested_name` when it contradicts the boolean, and is shared by both
`Refiner.run` and `repair_naming_conflicts`. It only ever recovers a change the
flag tried to hide; it never invents one.

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
    risk                  TEXT,               -- 'low' | 'medium' | 'high'
    reason                TEXT,
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
- Freshness is a content-hash of the current summaries compared against what's
  stored (not a count — refinement can change a summary without changing how
  many there are). `ask` rebuilds when that fails, so there is no
  user-visible index-building step

---

## 10. Query Modes (`ask.py`)

None of these open the IDA database.

| Flag | Mode | Mechanism |
|---|---|---|
| `"<text>"` | Semantic search | FAISS cosine similarity; auto-builds a stale/missing index; falls back to confidence ranking if faiss is unavailable |
| `--report` | Security report | All `security_relevant=1` entries, sorted by confidence |

(`--chain ADDR` and `--reindex` were cut 2026-08-19 as unused CLI bloat — see
§3b's scope-selector cut for the same pass. `kb.get_call_chain`/`_walk_chain`
were deleted with `--chain`, confirmed genuinely dead — single call site.
`--reindex` was mostly redundant with the content-hash auto-staleness check
above anyway; the one real gap it covered — switching `embed_model` in
config, which the content-hash can't detect since it hashes summary text, not
which model embedded it — is rare enough that deleting the `.faiss` files by
hand is an acceptable manual fallback. The standalone module-level
`ask.build_index()` function was also deleted here: already fully
unreachable from the CLI before this pass — nothing called it.)

`research_wingman.py status` reads the same sources and reports counts, staleness, and the
command to run next.

**On `confidence_query()`:** it takes no query text at all — it ranks *every*
analyzed entry by confidence, full stop. It therefore exists only as the
*automatic* fallback when `faiss`/`numpy` aren't installed, and that path
prints an explicit warning naming the query and saying it was NOT used. The
`--no-vector` flag that let a user request this deliberately has been removed:
asking a specific question and silently getting an unfiltered
ranked-by-confidence list is a footgun, and there is no reason to opt into it
when real semantic search is available.

---

## 11. Configuration Reference

Two tiers, both defined in `llm_renamer/config.py`.

**Tier 1 — shipped in `config.json`.** The settings a user is expected to edit,
plus (as of 2026-08-16) explicit overrides for the prompt-content caps —
promoted out of Tier 2 specifically so they're never invisible again (see
§7.1d for why that mattered):

```json
{
  "ollama": {
    "url": "http://localhost:11434",
    "model": "gemma4:26b",
    "embed_model": "nomic-embed-text"
  },
  "analysis": {
    "confidence_threshold": 0.65,
    "skip_high_risk": true,
    "max_pseudocode_lines": 1000,
    "max_imported_apis_shown": 15,
    "max_referenced_strings_shown": 12,
    "max_code_referrers_shown": 5,
    "max_unanalyzed_neighbours_shown": 5,
    "max_call_site_snippet_lines": 20,
    "max_related_summary_chars": 160
  },
  "graph": {
    "max_import_refs_per_node": 20,
    "max_string_refs_per_node": 20,
    "max_constant_operands_per_node": 64
  },
  "kb": {
    "repair_max_rounds": 3,
    "refinement_confidence_skip": 0.7
  }
}
```

**Tier 2 — code defaults in `_TUNING_DEFAULTS`.** Not in `config.json`, but any
key can be overridden by adding it there; `load_config` deep-merges the file
over the defaults. The prompt-content-cap keys above are declared here too
(so their default/rationale is documented in one place even for a user who
never opens `config.json`) — the file's copy is what actually applies.

| Group | Keys |
|---|---|
| `ollama` | `timeout_seconds`, `temperature`, `num_ctx` |
| `analysis` | `max_name_length`, `min_pseudocode_lines`, `max_pseudocode_lines` (default 200 in code; **1000** in the shipped file, §7.1d), `uncertain_prefix` (default `"maybe_"`), `uncertain_prefix_max_confidence` (default 0.7), `high_risk_confidence_override` (default 0.8), `max_imported_apis_shown` (15), `max_referenced_strings_shown` (12), `max_code_referrers_shown` (5), `max_unanalyzed_neighbours_shown` (5 — NOT a cap on real neighbour summaries, see §7.1d), `max_call_site_snippet_lines` (20), `max_related_summary_chars` (160, used by `diff.format_related_note`, §16.5) |
| `policy` | `analysis_candidate_prefixes` (default `["sub_"]`), `auto_generated_prefixes`, `vague_names_blacklist`, `conflict_suffix_max` |
| `scoring` | `sink_bonus`, `input_reachable_bonus`, `low_complexity_bonus`, `low_complexity_threshold`, `high_complexity_bonus` (default 3, added 2026-08-13), `high_complexity_threshold` (default 20), `high_complexity_caller_max` (default 3), `xref_focus_thresholds.*` |
| `graph` | `dangerous_sinks`, `input_sink_apis`, `max_import_refs_per_node` (20), `max_string_refs_per_node` (20), `max_constant_operands_per_node` (64) — the per-node caps are separate from the per-function prompt caps above (graph annotation data, e.g. mapview/scoring, not what's sent to the LLM); `dangerous_sink_calls` detection itself is collected before any of these caps apply, so a sink call can never silently disappear from risk detection |
| `kb` | `refinement_confidence_skip` (code default 0.85; shipped 0.7, §8.1), `repair_max_rounds` (code default 5; shipped 3, §8.2) |
| `search` | `min_similarity` (default 0.55, raised from 0.45 on 2026-08-13 — below it `ask` reports "no confident match" instead of padding out top-k; a nonsense query scored 0.456-0.466 against a real 526-function KB and still returned noise, and every genuine #1 hit across 8 real test queries landed at 0.65+, so the floor was set well above the nonsense ceiling on purpose — this config exists to favor precision over recall), `risk_boost` (default `{low:0.0, medium:0.03, high:0.07}`), `security_relevant_boost` (default 0.02). The boosts are small on purpose: they re-order near-ties so a risk-oriented question surfaces the genuinely dangerous function, without overriding raw semantic relevance. |
| `diff` | `self_consistency_min_prompt_chars` (default 20000 — above this, `compare_functions` takes a second independent sample and reconciles disagreements, see §16.4), `tiebreak_model` (default `null` — reuse the primary model; set to a different installed model, e.g. `"gpt-oss:20b"`, to get a genuinely independent second opinion on the reconciliation call, not just a re-roll of the same model), `tiebreak_think` |

**Paths are not configurable.** Every filename that used to live under
`output.*`, `graph.cache_filename`, `kb.sqlite_filename` and
`kb.faiss_filename` is now derived by `workspace.Workspace` from the database
path. `--workspace DIR` relocates the whole directory if needed.

---

## 12. CLI Reference

The free `map` overview is the default, no-commitment entry point; subcommands
exist for scripting and for targeted spending. `research_wingman.py` rewrites
its own argv so that default is what a bare invocation gets:

```
research_wingman.py                  → discover a .i64 in the cwd, then `map <that>`
research_wingman.py target.i64       → `map target.i64`
research_wingman.py --all target.i64 → `analyze target.i64 --all`
```

`_normalize_argv()` prepends `map` whenever the first argument is neither a
known command nor a flag (the free, no-commitment overview), and prepends
`analyze` when `--all` appears bare with no subcommand — the "point at a
sample and walk away" case. A raw (non-`.i64`/`.idb`) sample is built into a
database first, via a fresh subprocess (`_create-database`), by any command
that actually needs IDA open (`analyze`, `apply`, `map --build`) — `ask`/
`status`/`export`/plain `map` resolve to an existing `<sample>.i64` if one's
already there, but never build one just to report "no analysis found".

```
python research_wingman.py COMMAND DATABASE [options]

Commands:
  map       Browse the cached graph. No LLM; no IDA except --build.
  analyze   Analyze a scope with the LLM. Never modifies the database.
  apply     Write approved renames into the database. Never calls the LLM.
  ask       Search the analysis. Does not open the database.
  status    Report progress and what to run next.
  export    Write the knowledge base to a review JSON file.
  diff      Compare an old and a patched database (§16). Never modifies either.
  batch     Run the full --all pipeline (build + analyze + apply) on every
            sample in a folder, one at a time, one subprocess per sample.

Common to every command:
  DATABASE               Path to the .i64 IDA database (positional)
  --workspace DIR        State directory  (default: <database>.wingman)
  --config PATH          config.json path (default: llm_renamer/config.json)

analyze / ask / diff also accept:
  --ollama-url URL       Override the Ollama server URL
  --model NAME           Override the Ollama model
  --profile {vuln_research,malware}
                         Analysis prompt profile -- only `analyze` actually
                         consults this; `ask`/`diff` accept it but currently
                         ignore it. Omit it on `analyze` and it prompts
                         interactively before doing anything else. Prompt
                         text for both profiles lives in prompts/*.md.

map:
  --build                Build or refresh the call graph (needs IDA, no LLM)
  --suspicious [N]       Highest-scoring unnamed functions (default 25)
  --find QUERY           Search names, referenced strings, imported APIs
  --explore NAME         One function: neighbours, strings, imports, sinks
  --paths [N]            Entry point -> memory sink paths (default 10)

analyze  (exactly one scope selector is REQUIRED):
  -f, --function NAME…   These functions + their full callee subtree, by name or 0xADDR
  --top N                The N highest-scoring unnamed functions
  --all                  Every auto-named function (the overnight run)

  --limit N              Stop after N LLM calls; rerun to continue
  --redo                 Re-analyze functions that were already done
  --no-apply             Analysis only; do NOT write to the database (apply is the default)
  -y, --yes              Skip the cost confirmation prompt
  --no-refine            Skip the top-down refinement pass
  --no-report            Skip the macro capability report (only fires for
                         --all + --profile malware anyway -- see §17)

  To start a database over, delete its <database>.wingman/ directory --
  that's the entire state, so there is no dedicated reset flag.

apply:
  --dry-run              Show what would change; write nothing
  -y, --yes              Skip the write confirmation prompt

ask:
  QUERY                  Free-text question (position-independent)
  --top N                Result count  (default: 20)
  --security-only        Only security_relevant entries
  --report               All security-relevant functions

report:
  (no flags beyond --workspace/--config/--ollama-url/--model -- regenerates
  the capability report from the existing KB + cached call graph, no IDA
  needed. See §17.)

export:
  -o, --out PATH         Output path  (default: <workspace>/review.json)

diff  (takes OLD_DATABASE and PATCHED_DATABASE, both positional; exactly one of):
  --auto                 Pair functions automatically (§16.1) -- needs both call
                         graphs built via `map --build` first
  --pair OLD PATCHED     A matched function (name or 0xADDR) in each database;
                         repeatable, for manual pairing (e.g. from BinDiff)
  --max-lines N          Pseudocode line cap per function (default: 2000)
  -o, --out PATH         Output path (default: <patched>.wingman/diff_vs_<old>.json)
  --no-report            Skip the macro diff-summary report (§17)

batch  (FOLDER is positional; --profile is REQUIRED, no per-sample prompt):
  FOLDER                 Directory of raw samples and/or .i64 databases
  --profile {vuln_research,malware}
  --redo                 Re-analyze functions already done, for every sample
  --limit N              Stop each sample's analysis after N LLM calls
  --no-report            Passed through to every per-sample subprocess
  --config, --ollama-url, --model
                         Same meaning as elsewhere; passed through to every
                         per-sample subprocess

  Each sample runs `--all --profile ... -y` in its own subprocess -- same
  isolation reasoning as diff's per-database subprocess model (§16.6): one
  sample crashing or getting AV-quarantined mid-run doesn't take the rest of
  the batch down with it. Files research-wingman itself writes next to a
  sample (`.i64`, `.id0-3`, `.nam`, `.til`) are skipped when scanning the
  folder, so a batch never re-ingests its own output as another sample --
  everything else it writes lives inside `<sample>.wingman/`, never loose
  next to the sample, so there's nothing else to filter out.
```

`ask` accepts its question before or after other flags. Argparse cannot bind a
second optional positional across an intervening flag, so `main()` uses
`parse_known_args` and folds stray non-flag words into the query; leftover
tokens starting with `-` still raise an error.

**Output files** (all in `<database>.wingman/`):

| File | Written by | Purpose |
|---|---|---|
| `knowledge_base.sqlite` | `analyze`, `apply` | All state — results, verdicts, applied flags |
| `call_graph.json` | `analyze` (full mode) | Cached annotated call graph |
| `kb_vectors.faiss` + `.map` | `ask` (on demand) | Semantic index |
| `audit.jsonl` | `analyze`, `apply` | Append-only trail of every action taken (not a restatement of the analysis -- see §7.5) |
| `llm_responses.json` | `analyze` (both passes) | Every raw LLM JSON reply, verbatim, one array, atomically rewritten per call |
| `review.json` | `export` | One-way human-readable snapshot |
| `diff_vs_<old-name>.json` | `diff` | Full pairing breakdown (`noise`/`candidate`/`new`/`removed`/`new_noise`/`removed_noise`, not just what got an LLM call) plus every verdict. Written to the *patched* side's workspace, **incrementally after every single item** (not just once at the end) — see §16.6 |

---

## 13. Invariants and Quality Rules

1. **Never rename below `confidence_threshold`** (default 0.65; this
   project's shipped `config.json` currently overrides it to 0.6, §11)
   without flagging for human review. The flag *is* the `maybe_` name prefix
   (`uncertain_prefix`), applied programmatically for anything in
   `[confidence_threshold, uncertain_prefix_max_confidence)` — see §7.4 and
   `validator.py`.

2. **Uncertain callee summaries are labelled, not silently injected.**
   Any callee with `confidence < 0.6` gets `[LOW CONFIDENCE X.XX]` in the prompt.

3. **One refinement pass.** `Refiner.run` visits each function exactly once
   (`phase4_refined` is set regardless of outcome). The separate
   `repair_naming_conflicts` pass (§8.2) may revisit a function across its
   rounds, but only when a deterministic detector flags it — never speculatively.

4. **`security_relevant=true` has a narrow definition.** The function must
   demonstrably touch user-controlled data or perform memory operations without
   visible bounds checks. Proximity is not sufficient.

5. **Real recovered names are never overwritten; provisional names are.**
   Analysis candidates are `sub_` functions only (`analysis_candidate_prefixes`);
   `-f/--function` bypasses that filter to target a specific named function. At
   write time `apply` re-checks the database's current name: it overwrites
   *provisional* names (IDA auto-generated, the tool's own `maybe_` hedge, and
   `unknown_libname_` stubs) — which is what lets a confidence-upgrade re-apply —
   but refuses real recovered names (library/symbol/import, or an analyst's
   rename), preserving ground truth. IDA function comments written on apply are
   repeatable so they appear at every call site.

6. **Xref filtering is a weight, not a hard cutoff.**

7. **The analysis is stored whether or not the rename is accepted.** Summary
   and security fields are independent of the rename decision and valuable for
   callee injection.

8. **Address format is canonical hex.** All KB primary keys are `"0xABCD"`
   (uppercase hex, `0x` prefix), normalised by `kb._addr_to_hex`.

9. **`pipeline.analyze()` never writes to the IDA database; `pipeline.apply()`
   never calls the LLM.** They remain two separate functions with no shared
   code path — that *function-level* separation is the real invariant and it
   is what makes the expensive operation safe to rerun and the irreversible
   one cheap to preview. At the CLI surface, `research_wingman.py analyze` now
   **applies by default**: it calls `analyze()` then `apply()` in sequence
   within one command. This is a UX
   default, not a merge — the write step is still exactly `pipeline.apply()`
   with all its safeguards (analyst-name protection, idempotency). To analyse
   without writing, pass `--no-apply`, then preview with
   `research_wingman.py apply --dry-run`. So the command *default* writes;
   the *functions* never blur.

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
- **`sub_` candidates only** (by default). Only still-unnamed `sub_` functions are
  analysis candidates (`analysis_candidate_prefixes`); named functions and trivial
  auto stubs (`j_`/`nullsub_`/`locret_`/`loc_`) are skipped as not worth an LLM
  call. Their summaries can still be written to the KB for callee context. Use
  `-f/--function` to analyze a specific named function regardless.
- **No interprocedural taint analysis.** `input_reachable` is still a
  call-graph-only heuristic (some path exists from an entry point, no
  argument/dataflow awareness). As of 2026-08-11, `sink_argument_taint` (§7.1d)
  adds real but strictly single-function-local dataflow — whether a specific
  dangerous call's argument traces back to *that function's own* parameter,
  via Hex-Rays ctree traversal. It does not follow taint across a call
  boundary (a value tainted three functions up the chain won't be detected at
  the sink unless it's still visible as this function's own parameter), and
  `this->field` counts as parameter-derived even when the field holds an
  internal constant, not genuinely external input.
- **Not a vulnerability proof.** The output is a prioritised reading list with
  semantic annotations. A human researcher confirms findings.
- **No fuzzing harness generation.** Out of scope.

---

## 16. Cross-Binary Diff (`diff.py` + `autopair.py`)

`research_wingman.py diff OLD_DATABASE PATCHED_DATABASE (--auto | --pair OLD PATCHED...)`
compares two versions of the same binary and surfaces what's worth a human's time.
It never writes to either database. Two independently-loaded call graphs are its
only inputs beyond the databases themselves — no third-party diffing tool required.

### 16.1 Auto-pairing (`autopair.auto_pair`)

Two passes over `nodes_old: dict[int, CallNode]` / `nodes_patch: dict[int, CallNode]`
(loaded via `CallGraph.load`, so both call graphs must already be built):

1. **Exact name match.** For every named (non-`sub_`-style) function in the old
   graph, look up the same name in the patched graph. One match pairs them
   directly; multiple matches (rare — overloads/templates demangling identically)
   disambiguate via the structural score below, among just those candidates.
2. **Structural greedy match**, for whatever is left unnamed on both sides (the
   stripped-binary case): score every remaining old/patched pair by
   `0.35·size_similarity + 0.25·block_count_similarity + 0.30·named_callee_jaccard
   + 0.10·caller_count_similarity`, prefilter at score > 0.5, then greedily assign
   highest-score-first, one match per address.

### 16.2 Classification (`autopair.classify`)

Each pair from §16.1 gets one of three categories, cheaply and deterministically
(no LLM):

- **`unchanged`** — identical `size_bytes`, `basic_block_count`, AND
  `constant_operands` (§5.3a, added 2026-08-11 — closes a real gap: many
  x86-64 immediate encodings are fixed-width regardless of value, so a
  changed constant can leave size/block-count alone untouched) on both
  sides. Skipped for free. A pair that's identical on size/BB but NOT on
  constants is promoted to `candidate` (`promoted_by_constants: true`) rather
  than silently staying `unchanged` — see §5.3a for validated results and a
  known, self-correcting false-positive source (WPP trace IDs).
- **`noise`** — the name matches a known compiler/library-generated identity: WIL
  telemetry/feature-staging helpers (`wil_details_*`, `Feature_\w+__private_*`) or
  the MSVC adjustor/virtual-thunk mangling marker (`WCFA@EAA` in the demangled
  name). A hand-written security fix is implausible inside either. Skipped for
  free. Deliberately does **not** skip on size/block-count alone — a
  single-branch bounds-check helper being small doesn't mean a change inside it
  is insignificant, and the local LLM call to check is cheap. (An earlier
  version had a `<32 bytes / <=2 blocks` auto-noise threshold; removed after
  auditing showed it never actually fired on real data and was a pure latent
  false-negative risk.)

  The `Feature_*__private_*` pattern was originally `Feature_\d+__private_`
  (bare numeric feature ID) and silently under-matched: real Windows builds use
  *descriptive* feature IDs too, e.g. `Feature_Servicing_MSRC106366__private_
  IsEnabledFallback` and `Feature_NVBugFixes2507__private_
  IsEnabledDeviceUsageNoInline` — confirmed live 2026-08-11 against real
  ntfs.sys/http.sys pairs, where this boilerplate showed up as spurious
  new/removed churn (see §16.3) rather than being caught here, since the exact
  same accessor pair gets a *different* feature ID on every build and is never
  name-matched to begin with. Broadened to `Feature_\w+__private_`.
- **`candidate`** — everything else. Gets a real LLM call (§16.4).

---

## 17. Macro Reports (`report.py`)

A single LLM call over already-completed per-function analysis, producing a
human-readable narrative (plain markdown) instead of the tool's usual
per-function JSON. Two kinds, both returning `(markdown_text, meta)` and
touching no disk themselves — writing the file and printing progress is the
caller's job (`research_wingman.py`), same separation `diff.py`/`autopair.py`
already follow:

- `generate_capability_report(config, kb, graph)` — malware capability + IOC
  report. Triggers automatically at the end of `analyze --all --profile
  malware` (checked against `config["analysis"]["profile"]`, the *resolved*
  profile, not `args.profile` directly, since the profile can be filled in
  interactively when `--profile` wasn't passed). Gated on `--all` specifically
  — a partial scope's report would be misleading — and on the malware profile
  only: the capability/IOC template doesn't fit a `vuln_research` run.
  `--no-report` opts out. Also available on demand via the standalone
  `research_wingman.py report DATABASE` command, which reads the existing KB
  + cached call graph directly (no IDA needed, same category as `ask`/
  `status`) — useful to re-roll the synthesis call or regenerate after
  further refinement without rerunning analysis.
- `generate_diff_report(config, pairing_report, results)` — what-changed
  narrative from a completed `diff` run. Triggers at the end of `cmd_diff`
  (both `--auto` and `--pair`) when there's at least one reportable entry;
  `--no-report` opts out here too. Filters `results` (the same list already
  written to `diff_vs_<old>.json`) to entries where `meaningful_diff_found`
  or `security_relevant` is true, plus every new/removed function (a change
  by definition) — `[NO DIFF]` and error entries are dropped as noise for a
  macro narrative, not evidence.

### Context engineering

Both call `OllamaClient.generate_text_sized` — a free-form sibling to
`analyze_sized` added alongside this feature (no `format=json` constraint,
same auto-sizing/retry-on-truncation via `size_num_ctx`/`_CTX_BUCKETS`). The
capability report's prompt shape, validated live 2026-08-19 against the
1bb0d16 sample (274 of 451 approved functions were security-relevant, ~27K
prompt tokens, num_ctx auto-sized to 32768–65536 depending on the run, 128s):
full detail (name, risk, summary, `interesting_behaviors`) for
`security_relevant=1` rows, risk-ordered high-first, plus a compact
names-only list for everything else (redundant bulk otherwise, not signal),
plus a small entry-point hint list (security-relevant rows with
`caller_count == 0` in the graph) so the model has a structural anchor
without needing the full edge list. Manual verbatim spot-check against the
source evidence that run found zero hallucinated IOCs — every specific claim
checked (domain, ports, a magic constant, SSH/TLS-mimicking algorithm-name
strings) traced back to a real `interesting_behaviors` bullet the model was
actually given. It also correctly produced an honest negative on a benign
sample with no security-relevant functions at all ("No malicious
capabilities can be identified... No concrete indicators of compromise were
present") rather than forcing a fabricated narrative to fill the template —
confirmed live on `0287399d...` via the `--all` auto-trigger.

Not live-verified end to end: the `diff`-mode path is unit-tested
(`tests/test_report.py`) but has not been run against a real `diff --auto`
call with two paired sample databases.

### 16.3 New/removed detection (`autopair.find_new_and_removed`)

A named function present on only one side is invisible to §16.1 by construction —
it only ever matches starting from a name/candidate that exists on *both* sides.
Computed as the complement of the matched-address sets from `auto_pair`'s output:
named-and-unmatched patched addresses are `new`; named-and-unmatched old addresses
are `removed`. Each gets its own single-sided LLM call
(`diff.summarize_new_function`, §16.4) rather than only ever being seen secondhand
through whatever candidate happens to call it.

Real case that forced this (2026-08-07): a patch added `CClfsLogCcb::CheckReservation`/
`::RecordReservation` as brand-new helpers, called from 7 separately-changed
candidate functions. Without §16.3, all 7 got diffed, but the new helpers
themselves — arguably the actual fix — were never looked at directly.

**Noise applies here too (added 2026-08-11).** Returns a 4-tuple —
`(new, removed, noise_new, noise_removed)` — instead of 2: any new/removed
function whose name matches `is_noise_name` (§16.2) is split into the noise
lists instead of getting an LLM call. This is exactly the WIL feature-staging
churn case: `Feature_<id>__private_IsEnabledFallback`/
`IsEnabledDeviceUsageNoInline` carries a different `<id>` on every build, so it's
never a §16.1 matched pair, only ever new+removed — meaning every single
`diff --auto` run against a WIL-using Windows binary would otherwise burn 2+ LLM
calls and 2+ console entries on it, every time. `cmd_diff` still records
`noise_new`/`noise_removed` in the JSON report (counts printed too:
`new=N (+M noise)`) — nothing is silently dropped, it just doesn't cost a call.
Real effect measured on the same run: ntfs.sys went from 12 LLM calls to 8,
http.sys from 4 to 2.

### 16.4 LLM prompts (`diff.py`)

Two shapes:

- **`compare_functions(config, name, old_code, patched_code, related_note)`** — one
  prompt, both full pseudocode bodies, asks for a `differences` list (see below).
  Told explicitly that Hex-Rays renumbers locals independently per decompilation
  (`v12` in OLD isn't `v12` in PATCHED) and to ignore cosmetic reordering.
- **`summarize_new_function(config, name, code, situation, related_note)`** —
  `situation` is `"new"` or `"removed"`, selects between two system prompts (the
  removed-function one is framed in the past tense: "what the function *did*").
  Asks for `summary` / `security_relevant` / `risk` / `explanation`. Unchanged
  single-shape schema — the multi-difference problem below is specific to
  *comparing two versions*, not summarizing one.

Both size `num_ctx` to the actual prompt (`_size_num_ctx`: ~2.86 chars/token,
bucketed to 8192/16384/32768/65536/131072) rather than trusting Ollama's flat 8192
default. This matters concretely: a large old+patched pair silently truncates to
just the old half at the default, and the model correctly reports it can't compare
rather than guessing — a safe failure mode, but a useless one if nobody notices the
prompt was too big. Measured: a 44.7 KB combined prompt needed 32768 to actually see
both halves; it silently degraded at 8192.

**`differences` list, not a single verdict (added 2026-08-11).** The schema used
to ask for "the" (singular) concrete logic difference. Root-caused after
`NtfsWriteRawEncrypted` (ntfs.sys, ~7200 bytes, the largest/most complex pair in
that run) returned three *qualitatively different* stories across otherwise
identical runs — a `ProbeForRead` refactor twice, then a bounds-check/loop-
termination story once. This wasn't sampling noise: the function genuinely has
multiple real differences, and each pass reported whichever single one it
happened to notice. Fixed by asking for a list instead:

```json
{"differences": [
  {"meaningful": true|false, "summary": "...", "security_relevant": true|false,
   "risk": "low"|"medium"|"high", "explanation": "..."}
]}
```

`_normalize_result` parses this and derives the single-verdict fields the rest of
the pipeline reads (`meaningful_diff_found` = any entry meaningful,
`security_relevant` = any entry security-relevant, `risk` = max across entries,
`diff_summary`/`explanation` = every entry's text joined) via
`_aggregate_differences` — so callers written against the old flat shape (console
tagging in `cmd_diff`, `apply`/`ask` consumers if any existed) don't need to
change. Also tolerates the model reverting to the old flat shape entirely
(wraps it into a one-entry list) — schema drift from a local model has bitten
this module more than once (see the key-alias note below), so the parser stays
permissive rather than assuming the prompt is always followed exactly.
Re-verified on the same `NtfsWriteRawEncrypted` pair: a single call now reports
*both* real differences (the `ExtendedEncryptedDataInfoSignature` bounds check
and the loop-termination tightening) instead of one at random.

**Self-consistency sampling (`compare_functions`, added 2026-08-11).** Above
`diff.self_consistency_min_prompt_chars` (default 20000 chars — large/complex
pairs only, not every call), a second independent sample is taken and compared
against the first (`_drafts_agree`: same `meaningful_diff_found` /
`security_relevant` / `risk`). If they agree, the first draft is returned with
`self_consistency: {samples: 2, agreed: true}`. If they disagree, a third call
(`_synthesize_disagreement`, optionally routed to a different
`diff.tiebreak_model` for a genuinely independent second opinion) re-reads the
actual OLD/PATCHED code and produces a reconciled list — explicitly instructed
that disagreement often means each draft found *different real* differences
that should be merged, not that one is simply wrong. The result carries
`self_consistency: {samples: 3, agreed: false, flagged_for_human_review: true,
draft_1: ..., draft_2: ...}` so the disagreement stays visible in the JSON
report even after reconciliation — `cmd_diff` also prints a `[!] VERDICT
UNSTABLE` line to the console. Real validated case: `CryptMsgGetParam`
(crypt32.dll) — two disagreeing drafts were merged into 5 real differences,
including a genuine new bounds check (`*pcbData >= 4` before writing) neither
draft's aggregate verdict alone fully captured.

Both the second sample and the synthesis call are best-effort, not required:
if either raises `LLMError`, `compare_functions` degrades gracefully instead of
losing the (already-good) first draft — `self_consistency` gets a
`second_sample_failed`/`synthesis_failed` note instead of a crash. Verified with
mocked failures in `tests/test_diff.py`; without this, self-consistency would
have made large-prompt reliability *worse*, not better (more LLM round-trips
per item = more chances to hit the truncation failure below).

**Key-drift tolerance.** The local model has produced at least three different
spellings of what's now derived data, not a model-supplied field, across
validation sessions: `meaningful_diff_found`, `meaning_diff_found`,
`meaning_found`. The last one (confirmed live 2026-08-11 against ntfs.sys)
silently mistagged two real diffs as `[NO DIFF]` because only the first typo was
tolerated. Since `meaningful_diff_found` is now *derived* from the
`differences` list (not trusted directly from the model) this whole class of
bug is structurally closed for that field, though `_normalize_result` still
resolves any top-level key containing both `"meaning"` and `"found"` as a
fallback when the model reverts to the old flat shape.

**Retry-on-truncation (`_call_llm`, added 2026-08-11).** Ollama's `num_ctx`
covers prompt + response combined (no separate output cap is set), so a
response needing more room than what's left in the chosen bucket gets cut off
mid-generation — confirmed live on crypt32.dll's `InitCmsRecipientEncodeInfo`:
"Unterminated string" from a response that just stopped mid-JSON-string,
plausibly made *more* likely by the multi-difference schema asking for longer
responses. On that specific failure shape (`_is_truncation_error`: JSON-parse
failure or the model burning its whole budget on `thinking`), `_call_llm`
retries **once** with the next context bucket up before giving up — not
retried for network/HTTP errors, where more context wouldn't help. Shared by
all three call sites (`compare_functions`, `summarize_new_function`, the
synthesis call), so every LLM round-trip in this module gets the same
protection. Prints a `[retry]` line when it fires (added after an earlier
verification attempt found the mechanism otherwise has zero observability —
a failed-even-after-retry item's `error` record carries no `num_ctx_used`,
so there was no way to tell "retry never fired" from "retry fired and failed
anyway" just by reading a run's output).

**Confirmed firing and succeeding live (2026-08-11), not just unit-tested:**
initial verification attempts used `--pair` (no `related_note` padding, so
the prompt stayed under the 20000-char self-consistency threshold — a
methodology gap, not evidence the retry doesn't work) and one direct re-test
of the known-failing pair happened to succeed on the first attempt (retry
never needed that specific time — truncation is non-deterministic, not a
hard limit at that size). A full `diff --auto` re-run against crypt32.dll
reproduced the original conditions faithfully and caught it directly:
`InitCmsRecipientEncodeInfo` truncated at `num_ctx=8192` ("Unterminated
string..."), the `[retry]` line fired, retried at `num_ctx=16384`, and
**succeeded** — producing a real 3-difference result including a genuine new
finding (a bounds check added on `ExtraInfo.pbData`, ensuring at least 4
bytes before reading it, `risk=medium`, security-relevant) that would
otherwise have been lost entirely.

**Per-item crash isolation and incremental writes (`research_wingman.cmd_diff`,
added 2026-08-11).** Before this, an `LLMError` from any single item raised
uncaught out of `cmd_diff`'s loops and crashed the whole run — and since
results were only written to disk once, at the very end, this discarded
*everything* computed so far. Confirmed at real cost: a crypt32.dll run lost
1000+ lines of completed analysis (including several `risk=high` findings)
to one truncated response after ~40 minutes of real LLM calls. Fixed two ways,
together: (1) each of the three loops (new/removed/candidate pairs) wraps its
LLM call in `try/except LLMError`, recording `{**identifying_fields, "error":
str(e)}` and continuing instead of raising; (2) results are written to the
output JSON after **every** item (`save_progress()`), not just at the end.
Combined with the retry above, a re-run of the same crypt32.dll pair completed
all 140 items with exactly 1 item hitting the error path (isolated, the other
139 unaffected) — direct proof against the original failure.

### 16.5 Cross-candidate relatedness (`autopair.compute_relatedness` + `diff.format_related_note`)

For every address in one run's candidate+new (patched-side) or candidate+removed
(old-side) set, `compute_relatedness` walks each `CallNode.callee_addresses` and
records, per address, which *other* addresses in the same set it calls or is
called by — i.e. whether two things that both changed in this patch are
structurally connected. `format_related_note` renders each relation as one bullet
in the prompt: the neighbour's own already-computed **summary** (truncated to
`analysis.max_related_summary_chars`, default 160 chars, §11) if it's been
analyzed yet this run, else just its name. Never the
neighbour's full pseudocode body (prompt-size cost that scales with the size of
the related set). Omitted entirely when a function has no relations — never
padded.

**Processing order determines summary availability.** `research_wingman.cmd_diff`
processes `new` functions, then `removed` functions, then `candidate` pairs, each
building `summary_lookup: dict[addr, str]` as it goes — so by the time a candidate
references a new/removed helper, that helper's real summary is usually already
available to quote. `autopair.sort_leaves_first` orders new/removed processing by
ascending calls-within-set count (a leaf like `...IsEnabledFallback` before the
`...IsEnabledDeviceUsageNoInline` wrapper that calls it) to maximize this further.
This is a heuristic, not a true topological sort — coverage is asymmetric in
practice (observed directly: a function processed before a callee it itself calls,
due to a tied sort key, only got that callee's bare name in its own note; the
callee's later-processed note carried the full summary back).

Candidate-to-candidate relatedness notes are name-only in practice — candidates are
processed last, so by construction no other candidate's summary exists yet when
building the current one's note. Not yet addressed; no real case has needed it.

### 16.6 Process model: one `.i64` open per process, always

idalib does not support opening a second database in the same process after
closing the first — it hangs silently (no error, no output, CPU time flatlines)
rather than raising, confirmed by actually running the naive version and watching
it hang for 4+ minutes before being force-killed. `diff` therefore shells out to a
hidden `_extract-pseudocode` subcommand
(`research_wingman.py _extract-pseudocode DATABASE --addr REF [--addr REF...] --out FILE`)
once per database — each subprocess gets its own idalib session, opens exactly one
`.i64`, extracts pseudocode for the requested addresses, writes JSON, exits. The
LLM comparison itself then runs in the parent process with **no database open at
all**. Any future feature touching two `.i64` files must follow this pattern.

### 16.7 `tools/winbindex_fetch.py`

Standalone script (stdlib only, not part of `llm_renamer`) for pulling real
Windows system binaries from [WinBinDex](https://winbindex.m417z.com) as `diff`
input, without a browser or BinDiff. Queries WinBinDex's per-filename JSON index
(hosted on `raw.githubusercontent.com`, gzip-compressed, keyed by SHA-256),
constructs the Microsoft symbol-server download URL from each build's timestamp
and page-aligned image size (`msdl.microsoft.com/download/symbols/<file>/<TS:08X><SIZE:x>/<file>`),
downloads, and **verifies the SHA-256 against WinBinDex's own metadata before
writing anything to disk** — a corrupted or wrong download is never silently used.
`--pull-latest-pair --branch BUILDPREFIX` picks the two newest consecutive builds
in one OS branch (e.g. `26100` for Windows 11 24H2) for exactly the `diff --auto`
input shape.

### 16.8 Validated results

On the session's `clfs_old`/`clfs_patch` pair (941 functions, known-correct BinDiff
pairing as ground truth): `--auto` recovered exactly the 3 real changed functions,
0 false positives / 0 false negatives, correctly classified all 5 WIL/telemetry
pairs as noise. Structural-fallback stress test (correlated name-blinding to
simulate a stripped binary): 100% correct matches at 30%/70%/100% of names
blinded. Independently re-run against a second, unrelated real pair pulled via
§16.7 (`clfs.sys` 10.0.26100.8875 → 8972, Windows 11 24H2, both amd64) with no
prior knowledge of what changed: found 14 candidates + 13 new + 2 removed out of
1307 functions, including a fix gated behind a feature flag literally named
`MSRC97927` (a Microsoft Security Response Center case ID baked into Microsoft's
own build metadata) doing an `_InterlockedExchange64` TOCTOU fix. Two findings
across both runs were manually verified character-for-character against raw
`_extract-pseudocode` output (not just trusted from the LLM verdict): the
`clfs_old`/`clfs_patch` `WriteMetadataBlock` fix, and the `MSRC97927`-gated
`CheckReservation`/`RecordReservation` pair.

**Honest scope caveat, not yet closed:** both validated pairs are old/patched
binaries where the two versions are a *tight* pair (>99% of functions
byte-identical after one focused change) — size/basic-block-count are strong
discriminators there. A heavily-refactored or differently-optimized recompile
would see more structural collisions in §16.1's fallback matcher; not tested.

**Second validation round (2026-08-11), three more real WinBinDex pairs, larger
and more complex than the CLFS baseline:**

- **ntfs.sys** (2960→2962 functions) and **http.sys** (3884→3882 functions),
  both 10.0.26100.8875→8972. This round is what surfaced and fixed the
  `meaning_found` key-drift, the blank-diff-summary gap, and the WIL noise
  under-matching described in §16.2–16.4 — all found via real, not synthetic,
  runs. ntfs.sys's patch touches `Feature_Servicing_MSRC106366` (an actual
  MSRC case ID) via a real `ProbeForRead`/bounds-check change in
  `NtfsWriteRawEncrypted`, the same pair that motivated the multi-difference
  schema change.
- **crypt32.dll** (4050→4120 functions, the largest and most-changed pair
  tested — 70 new functions, +20KB, vs. 2–4 new functions on the others). The
  whole patch turned out to be Microsoft adding **ML-KEM (post-quantum)
  support to CMS/PKCS#7** — dozens of new ASN.1 encode/decode functions for
  `KEMRecipientInfo`/`AuthEnvelopedData`, gated behind a
  `Feature_Servicing_PQ_CmsMlKem_Crypt32` flag threaded through nearly every
  core crypto entry point. 7 functions flagged `risk=high` in the new PQ
  parsing code. This run is also what surfaced the truncation-crash bug (§16.4)
  and validated its fix: the re-run completed all 140 items with exactly 1
  isolated error, versus a full crash and 1000+ lines of lost analysis before
  the fix.

### 16.9 Regression tests (`tests/`)

Everything found and fixed in the 2026-08-11 round above was originally
verified as one-off `python -c` commands during that session — real, but
disposable; nothing would have caught a regression short of another expensive
live run. Saved as a permanent `unittest` suite (stdlib only, no pytest — the
project has no third-party runtime dependencies and this follows the same
rule for tests):

- **`test_diff.py`** — `_normalize_result`'s differences-list parsing and all
  three observed key-drift spellings, `_aggregate_differences`'s
  risk-max/any-of rules, the old-flat-shape fallback, all five
  `compare_functions` self-consistency outcomes (below-threshold, agree,
  disagree-and-reconcile, and the two failure-degradation paths),
  `_call_llm`'s retry-on-truncation (retries and succeeds / skips network
  errors / skips at the max bucket).
- **`test_autopair.py`** — `is_noise_name`/`find_new_and_removed` against the
  exact real names that broke before the fix, plus `classify`'s
  constant-based promotion (identical-size-and-constants stays `unchanged`,
  differing constants promotes to `candidate`, a size mismatch is unaffected
  by the new logic, empty-constants-on-both-sides doesn't false-positive).
- **`test_call_graph.py`** — `_to_signed64`'s sign-normalization against the
  exact real unsigned-64-bit values observed live (`-1`, `-512`).
- **`test_prompts.py`** — `_render_graph_signals`'s taint-line rendering
  (tainted vs. untainted sink calls, singular/plural wording, missing-key
  safety).
- **`test_refiner.py`** — `Refiner.run()`'s LLM-error handling: a transient
  `LLMError` must leave the function's `phase4_refined` flag unset for a
  future retry, not `mark_refined()` it away permanently like the other
  (structural, rerun-proof) skip branches do (§8.1).

All LLM calls are mocked (`_call_llm`/`OllamaClient.analyze` patched
directly); IDA-dependent logic (`sink_argument_taint`'s ctree walk,
`_extract_constants`'s instruction scan) is fundamentally untestable without a
real `cfunc_t`/database and is validated live instead (§5.3a, §7.1d), not
unit-tested — same category as `_pseudocode`/`_strings`/etc., which also have
no unit tests for the same reason. 40 tests, ~2ms total, no network, no
Ollama, no IDA. Run: `python -m unittest discover -s tests -v`.
