# research-wingman — a reverse engineering copilot

Helps you work through an IDA Pro database: maps the binary for free, then
points a local LLM at the specific functions you care about — naming them,
summarizing them, and flagging the security-relevant ones.

Opens the `.i64` directly via **idapro** — no GUI, no plugin install.

---

## The idea

> **The call graph is a free map. The LLM is an expensive lens.**
> Look at the map, pick a spot, then spend.

Running an LLM over every function in a real binary is an overnight job and
mostly wasted — the bulk of any binary is logging, CRT glue and utility code.
So `research-wingman` splits into two halves:

- **`map`** — instant, no LLM. Entry points, imports, strings, call paths,
  which functions touch `memcpy` with attacker-controlled data. This answers
  most questions on its own.
- **`analyze`** — costs LLM calls, so it always requires an explicit scope and
  quotes the cost before spending it. There is no accidental overnight run.

---

## Just run it

```bash
python research_wingman.py target.i64
```

That's the free overview — entry points, imports, size, what's worth looking
at first. No LLM, nothing spent, no flags to remember.

Run `python research_wingman.py` with no arguments and it finds a `.i64` in
the current directory and shows the same overview. Point it at a raw sample
instead of a `.i64`/`.idb` and it builds one first — full IDA auto-analysis,
needs a few minutes on a large binary, then continues exactly as if you'd
handed it the database directly:

```bash
python research_wingman.py sample.elf --all
```

`--all` works bare like this with no `analyze` subcommand needed — it's the
"give it the sample and walk away" shorthand for the overnight sweep. Either
way, if `--profile` isn't given, it asks once, up front, which profile to
analyze with before spending anything.

```
────────────────────────────────────────────────────────────────────────
  target.i64   graph: 45210 functions
  analyzed: 128   security-flagged: 19   ready to apply: 96
────────────────────────────────────────────────────────────────────────
  Entry points:
  0x401000       DriverEntry                          6.0  callers=0     bb=41
  0x402A10       sub_402A10                            4.0  callers=0     bb=12
  ...
```

`map --suspicious`/`--find`/`--explore` go deeper for free from there. Once
you've picked a target, every `analyze` scope — `-f`, `--top N`, `--all`,
all of them — shows what it's about to spend and waits:

```
  Scope     : entry -> sink paths
  Functions : 7
  Cost      : ~7 LLM call(s), about 43s
  Go ahead? [Y/n]
```

The per-function rate is measured from your actual runs, so the estimate gets
accurate after the first one.

---

## Two rules

- **Analysis and writing are separate operations, in policy, not in timing.**
  `analyze()` never decides *whether* to write on its own — only `apply()`'s
  policy (never overwrite a real recovered/analyst name, resolve conflicts)
  ever does. But writing does not wait for the whole batch: by default,
  `research_wingman.py analyze` writes each function's approved rename and
  summary comment the moment it's approved, so a long run (`--all`, an
  overnight sweep) keeps the `.i64` continuously current instead of leaving it
  unchanged until everything finishes — interrupt it anytime and whatever was
  approved so far is already in the database. Pass **`--no-apply`** to stop
  after analysis and write nothing at all, then apply later with
  `research_wingman.py apply` (preview first with
  `research_wingman.py apply --dry-run`). One `apply()` pass still runs at the
  very end regardless, to pick up anything the top-down refinement pass (which
  runs after the main analysis loop) improved.
- **`apply` never calls the LLM.** It only writes what analysis already
  decided, refuses to overwrite an analyst's name, and is idempotent.

---

## A worked example

You're looking for a parsing bug in a network service.

```bash
# 1. Build the map once. Needs IDA, takes minutes, no LLM calls.
python research_wingman.py map target.i64 --build

# 2. Where does network data arrive and where does it end up?
python research_wingman.py map target.i64 --paths
```

```
  Path 1  (5 functions)
    0x401000  main
      └─ 0x401100  sub_401100
        └─ 0x401300  sub_401300   [recv]
          └─ 0x401400  sub_401400
            └─ 0x401500  sub_401500   [memcpy]
```

```bash
# 3. That's the interesting path. Analyze exactly those functions, not 45,000.
python research_wingman.py analyze target.i64 -f sub_401100 sub_401300 sub_401400 sub_401500

# 4. Or go straight at the header parser you spotted.
python research_wingman.py map target.i64 --find "Content-Length"
python research_wingman.py analyze target.i64 -f sub_401400

# 5. Read the results, then write them into the database.
python research_wingman.py ask target.i64 "unchecked length used in a copy"
python research_wingman.py apply target.i64 --dry-run
python research_wingman.py apply target.i64
```

---

## Commands

The worked example above already covers day-to-day use. This is the full
reference — exact flags for scripting, or for when you already know exactly
what you want.

### `map` — free, instant, no LLM

```bash
python research_wingman.py map target.i64                      # overview
python research_wingman.py map target.i64 --build              # build/refresh the graph (needs IDA)
python research_wingman.py map target.i64 --suspicious 25      # ranked by score
python research_wingman.py map target.i64 --find "recv"        # names, strings, imported APIs
python research_wingman.py map target.i64 --explore sub_401400 # one function in detail
python research_wingman.py map target.i64 --paths              # entry point -> memory sink
```

`--find` searches referenced strings and imports too, because they're cached in
the graph. Once the graph is built, none of this needs IDA open.

The ranking behind `--suspicious` is the xref heuristic: functions called from
1–3 places are unique code paths where bugs live; functions called from 50+
places are utilities. Add bonuses for calling a memory sink, for being
reachable from an input source, and (since 2026-08-13) for being substantial
*and* rarely called directly — a large function reached only through indirect
dispatch is exactly the shape a real entry point takes, and previously scored
no higher than a trivial one-block wrapper with the same caller count.

Sink/input-reachable bonuses depend on named imports, so they read `0` on a
statically-linked binary with no import table (common for embedded/IoT
malware) even when the binary clearly touches memory and network input —
`map`'s overview says so explicitly when it detects this, rather than letting
`0` read as "nothing dangerous here." `--suspicious` still works in that case
(everything else in the formula is structural, not import-based), it's just
the only free signal you have.

### `analyze` — scoped, priced

A scope is **required**:

| Scope | What it selects |
|---|---|
| `-f NAME...` | These functions **and their full callee subtree** (leaves-first, so context is real by the time the target is analyzed). The named targets themselves always get a fresh LLM call even if already done; pulled-in callees don't. |
| `--top N` | The N highest-scoring unnamed functions |
| `--all` | Every auto-named function (the overnight run) |

There is no downward radius flag: `-f NAME` already selects a function *and*
everything it calls, so a depth-capped second spelling of the same thing was
removed. Scope size is governed by the cost quote, not a depth cap.

For anything path-shaped ("entry point down to this sink", "everything
between A and B", "who calls this") — use `map --paths`/`--explore`/`--find`
to see it for free first, then `-f` the specific function names it turns up.
That two-step (look, then spend) was originally three separate paid scope
flags (`--callers`, `--between`, `--to-sinks`); they were cut because the
free `map` step already does the finding, and `-f` already does the spending
— a dedicated flag for each path shape was just a second way to say the same
thing.

Modifiers: `--limit N` LLM calls · `--redo` to re-analyze finished functions ·
**`--no-apply`** to stop after analysis without writing to the database (apply
is the default) · `-y` to skip the cost prompt · `--no-refine` to skip the
top-down refinement pass, keeping the call graph.

To start a database over, delete its `<database>.wingman/` directory (see
"Where state lives" below) — that's the entire state for that database, so
there's nothing else to reset.

Analysis runs leaves-first, so by the time a caller is analyzed its callees'
summaries are already in the prompt. Interrupt any run and rerun it — finished
functions are skipped (except `-f`'s own named targets, which always rerun by
design — see above).

### Profiles — `--profile`

`analyze` accepts `--profile {vuln_research,malware}` to pick which
system prompt does the analysis. Leave it off and it asks interactively,
once, before doing anything else — there's no silent default to forget about:

- **`vuln_research`** (default) — tuned for finding memory-safety bugs in real
  software: `security_relevant`/`risk` are framed around unbounded
  copies/user-controlled lengths/missing validation.
- **`malware`** — reframes the same fields around malicious capability
  instead (C2, persistence, evasion, propagation, payload), and explicitly
  asks for indicators (hardcoded IPs/domains/URLs, obfuscation routines) to be
  cited in `interesting_behaviors` rather than folded into a generic summary.
  Written after `vuln_research` was handed a function referencing a hardcoded
  C2 IP right next to an XOR-decryption call and named it
  `initialize_system_pool_and_dispatch_table` without ever mentioning the IP —
  memory-safety framing has no purchase on a statically-linked bot binary.

```bash
python research_wingman.py analyze sample.i64 -f sub_401000 --profile malware
```

Every system prompt in the tool (both profiles, plus refine/repair/diff) is a
plain-text file under `prompts/` at the repo root — open one directly to read
or edit exactly what the LLM is told.

`ask` and `diff` also accept `--profile` (inherited from the same shared flag
group) but currently ignore it — neither calls an analysis-phase system
prompt, so it's a no-op there for now.

### `diff` — compare an old and a patched binary

```bash
# Auto-pair everything and let the LLM look at what actually changed:
python research_wingman.py map target-old.i64 --build       # both need a graph first
python research_wingman.py map target-new.i64 --build
python research_wingman.py diff target-old.i64 target-new.i64 --auto

# Or pair specific functions yourself (e.g. from a BinDiff export):
python research_wingman.py diff target-old.i64 target-new.i64 \
    --pair sub_401000 sub_402100 --pair sub_401800 sub_402900
```

No BinDiff required for `--auto` — functions are paired by exact name across both
call graphs first, with a structural fallback (size / basic-block-count /
caller-count / shared-callee-name overlap) for whatever's unnamed on both sides.
Each pair is then classified `unchanged` (identical size and block count — skipped,
free), `noise` (matches a known compiler/library identity — WIL telemetry helpers,
MSVC virtual-thunk mangling — skipped, free), or `candidate` (gets one LLM call
comparing both full pseudocode bodies). A function that exists on only one side
(genuinely new or removed code — often the actual fix itself) gets its own LLM call
too, and everything that changed in the same run gets a short note about what else
nearby also changed, so the model isn't reasoning about each change in isolation.

Costs one LLM call per candidate/new/removed function, no cost prompt (unlike
`analyze`, there's no cheap way to price it before auto-pairing runs, and
auto-pairing itself is free) — check the printed `paired=… candidate=…` line if you
want to see the count before it starts spending.

```bash
python research_wingman.py diff old.i64 patched.i64 --auto --max-lines 3000
                                                    # raise the pseudocode cap for
                                                    # unusually large functions
python research_wingman.py diff old.i64 patched.i64 --auto -o report.json
```

Writes a report to `<patched>.wingman/diff_vs_<old>.json` by default: the full
pairing breakdown (every `noise`/`candidate`/`new`/`removed` entry, not just what
got an LLM call — nothing is silently unaccountable) plus every verdict.

### `batch` — the full pipeline across every sample in a folder

```bash
python research_wingman.py batch mal-samples/ --profile malware
```

For each raw sample in the folder (or a `.i64` left with no raw sibling):
build a database if needed, analyze every auto-named function, and apply
approved renames — exactly `--all` on one sample, just looped across a
folder. `--profile` is required (there's no per-sample prompt in an
unattended run). Each sample runs in its own subprocess, so one crashing or
getting AV-quarantined mid-run doesn't take the rest of the batch down with
it. `--redo`, `--limit N`, `--config`, `--ollama-url`, and `--model` all
pass through to every sample.

Files research-wingman itself writes next to a sample (`.i64`, `.id0-3`,
`.nam`, `.til`) are skipped when scanning the folder, so a batch never
re-ingests its own output as if it were another sample.

### `apply`, `ask`, `status`, `report`, `export`

```bash
python research_wingman.py apply  target.i64 --dry-run     # exactly what would change
python research_wingman.py apply  target.i64               # write renames + IDA comments
python research_wingman.py apply  target.i64 -y             # skip the write confirmation
python research_wingman.py ask    target.i64 "question"    # semantic search
python research_wingman.py ask    target.i64 "question" --security-only   # ...restricted to security-flagged results
python research_wingman.py ask    target.i64 --report      # every security-flagged function
python research_wingman.py status target.i64
python research_wingman.py report target.i64                # regenerate the macro capability report (no IDA needed)
python research_wingman.py export target.i64               # review.json
python research_wingman.py export target.i64 -o findings.json  # write somewhere other than <workspace>/review.json
```

`apply` re-checks each function's current name at write time, so anything
you've renamed yourself is left alone. Applied rows are marked — running it
twice is harmless. `-y` skips its write confirmation, same meaning as
`analyze`'s.

`ask` builds its semantic index automatically when it's missing or stale, by
comparing a content-hash of the current summaries against what's stored.
`--top N` caps how many results come back (default 20). `--security-only` narrows a plain-text query
(or its no-index confidence-ranked fallback) to security-flagged functions
only — `--report` already lists exclusively those, so it ignores the flag.
`ask`, `status`, and `report` don't open the database at all — `report`
specifically reads the existing knowledge base + cached call graph and
re-rolls the capability-report synthesis call, useful after further
refinement or just to get a different sample from the model without
rerunning analysis.

Analysis also exploits **embedded method-name strings**: Windows components
built with WPP tracing embed each function's own fully-qualified C++ name
(e.g. `CClfsLogFcbPhysical::ReserveAndAppendLog`) as a literal string. When a
function references one, it's elevated as the strongest naming hint, so names
track the binary's own ground truth where it exists.

---

## Where state lives

```
/malware/sample.i64
/malware/sample.i64.wingman/
    knowledge_base.sqlite     every result — the single source of truth
    call_graph.json           cached call graph
    kb_vectors.faiss (.map)   semantic search index
    audit.jsonl               append-only log of every action taken
    llm_responses.json        every raw LLM response, verbatim
    review.json               written by `research_wingman.py export`, on demand
    diff_vs_<old-name>.json   written by `research_wingman.py diff`, on the patched
                              side's workspace, one per old binary compared against
```

State follows the binary, not your shell, so you can never silently start over
and re-spend LLM calls.

Every command accepts `--workspace DIR` to put that state somewhere other
than `<database>.wingman/` next to the binary — useful when the database
lives somewhere you'd rather not write to, or you want two separate analysis
passes over the same `.i64` kept apart. Also `--config PATH` to point at a
`config.json` other than the shipped default.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **IDA Pro 9+** with `idapro` | IDA's headless Python package. |
| **Hex-Rays decompiler** | Needed for pseudocode. Functions without it are skipped and logged. |
| **Ollama** | [ollama.com](https://ollama.com). Can be on another machine (`--ollama-url`). |
| **Python 3.9+** | Any environment where `idapro` is importable. |
| *(optional)* `faiss-cpu`, `numpy` | Semantic search. Without them, `ask` ranks by confidence. |

```bash
ollama pull gemma4:26b
ollama pull nomic-embed-text        # only for semantic search
```

Only `analyze`, `apply`, and `map --build` need IDA. Everything else
runs off the workspace.

---

## Configure

`llm_renamer/config.json` is the whole user-facing config:

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
    "profile": "vuln_research",
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

`--ollama-url` and `--model` override `ollama.url`/`ollama.model` for one run
without editing the file — handy since `config.json` is shared across
whatever databases you point the tool at, so it's the wrong place for a
one-off. Same reasoning is why `--profile` is a flag and not just this file's
`analysis.profile`: switching between a Windows driver and a malware sample
shouldn't mean editing shared config back and forth every time.

The `max_*` keys above bound how much per-function content survives into the
LLM prompt (pseudocode length, imported APIs, strings, caller/callee
neighbours with no analysis yet). `max_pseudocode_lines` learned this the hard
way: at the old default of 200, a real 722-line malware dispatcher function
lost 72% of its body and, with it, 22 of 39 real callee names — see
ARCHITECTURE.md §7.1d for the full story. They're promoted into this file
specifically so they're never invisible again; `max_unanalyzed_neighbours_shown`
is the one exception worth calling out — it does *not* cap real neighbour
summaries (every analyzed callee/caller is always shown in full), only the
tail of neighbours with no analysis yet. A function that still exceeds
`max_pseudocode_lines` gets a `[N more lines truncated]` marker inside the
prompt (so the model knows it's seeing a partial body) *and* a console
`[WARNING]` naming the function and the key to raise — query
`KnowledgeBase.get_pseudocode_truncated()` for the full list after a run.

The `kb` keys tune the top-down refinement pass that runs after the main
analysis loop (`--no-refine` skips it entirely): `refinement_confidence_skip`
is the confidence a function needs to skip a second look (raised to 0.7 from
the code default of 0.85 — most of what a live run flagged as "low
confidence" at 0.85 was really just the model's normal range, not genuine
uncertainty); `repair_max_rounds` caps the deterministic naming-conflict
repair loop (lowered to 3 from 5 — healthy runs converge well before that;
see ARCHITECTURE.md §8.2 for the oscillation guard that makes low values safe).

Scoring weights, sink lists, name blacklists, and everything else not worth a
user's attention by default live in `llm_renamer/config.py` as Tier-2
defaults. Add any of them here to override.

---

## Rename policy

- Analysis candidates are `sub_*` functions only — named functions and trivial
  stubs (`j_*`, `nullsub_*`, `locret_*`, `loc_*`) aren't worth an LLM call. `-f`
  can still target a specific named function. At write time `apply` overwrites
  *provisional* names (`sub_*`, the tool's own `maybe_*`, IDA's
  `unknown_libname_*`) so a confidence upgrade can land, but refuses real
  recovered names (library/symbol/import, or an analyst's rename).
- Rejected if confidence is below `confidence_threshold`, or the name is
  vague, illegal, digit-leading, or over 64 characters.
- `risk` (the model's own "how dangerous would a wrong answer be here"
  severity, independent of its confidence) is a separate gate: `risk=high`
  is rejected *only* below `high_risk_confidence_override` (default 0.8) —
  at or above it, the rename goes through, but `risk=high` stays recorded in
  the KB so it's still visible when browsing later. Below the main
  `confidence_threshold` it's rejected anyway regardless of risk.
- Confidence in `[confidence_threshold, uncertain_prefix_max_confidence)`
  (default `[0.6, 0.7)`) gets approved but prefixed with `maybe_` — applied
  programmatically from the numeric confidence, not something the LLM is
  asked to do. Mirrors a `maybe_check_N` convention already used by a human
  analyst elsewhere in one real target binary.
- Collisions get `_2`, `_3`, … and fall back to an address suffix once those
  are exhausted, so a large family of identical proposals never fails outright.
- Rejections are recorded so they aren't retried. LLM *errors* are not, so
  those do get retried.

---

## Project layout

```
research_wingman.py     the CLI
prompts/                 every system prompt, one plain-text .md file each --
                         analyze (2 profiles), refine, repair, diff (4),
                         report (capability + diff summary) --
                         loaded by llm_renamer/prompts.py's load_prompt(),
                         never inline Python strings
llm_renamer/
  navigate.py            graph traversal: paths, neighbourhoods, search
  mapview.py             map rendering
  pipeline.py            analyze() and apply() — the two IDA-facing operations
  ask.py                 semantic search, KB status/confidence reports
  workspace.py           where state lives for a database
  kb.py                  SQLite knowledge base (single source of truth)
  call_graph.py          call graph construction and caching
  scorer.py              scoring and bottom-up ordering
  idapro_client.py       IDA context extraction
  llm_client.py          Ollama HTTP client (stdlib only)
  prompts.py             per-function prompt builder + load_prompt() (reads prompts/)
  family.py              structural twin detection (body_hash), shared by
                         prompts.py and refiner.py
  validator.py           output validation and snake_case sanitization
  renamer.py             the only place that calls idc.set_name
  refiner.py             top-down refinement pass
  embedder.py            semantic index
  export.py              review JSON writer
  audit.py               append-only JSONL log
  llm_log.py             aggregated raw-LLM-response JSON log
  report.py               capability + diff-summary synthesis reports
  autopair.py             cross-binary pairing, classification, relatedness (no LLM)
  diff.py                 old-vs-patched compare / new-removed summarize prompts
  config.py / config.json
tools/
  winbindex_fetch.py      pull real Windows binaries from WinBinDex for `diff`
tests/
  test_diff.py             diff.py regression tests -- run: python -m unittest discover -s tests
  test_autopair.py         autopair.py regression tests
  test_call_graph.py       call_graph.py's constant-operand sign-normalization
  test_prompts.py          prompts.py's taint-signal rendering
  test_refiner.py          refiner.py's LLM-error retry + duplicate-name gate
  test_family.py           family.py's normalize/hash + KB family queries
  test_report.py           report.py's prompt construction + diff filtering
                           (no LLM/IDA needed for any of these)
ARCHITECTURE.md          design reference
```

---

## Upgrading from `main.py` / `query.py`

Both are gone — `research_wingman.py` is the only entry point now.

| Old command | New command |
|---|---|
| `main.py --database DB` | `research_wingman.py analyze DB --all` |
| `main.py --database DB --quick` | removed — `-f` on a small scope is usually just as fast |
| `main.py --database DB --function F` | `research_wingman.py analyze DB -f F` |
| `main.py --database DB --limit N` | `research_wingman.py analyze DB --limit N` |
| `main.py --database DB --apply` | `research_wingman.py analyze DB --apply` |
| `main.py --database DB --apply-file F` | `research_wingman.py apply DB` |
| `main.py --database DB --build-index` | (automatic — `research_wingman.py ask` builds it) |
| `main.py --database DB --clear-checkpoint` | removed — delete `<DB>.wingman/` to start over |
| `main.py --database DB --no-resume` | removed — delete `<DB>.wingman/` to start over |
| `main.py --database DB --skip-refine` | `research_wingman.py analyze DB --no-refine` |
| `query.py "question"` | `research_wingman.py ask DB "question"` |
| `query.py --report` | `research_wingman.py ask DB --report` |
| `query.py --chain ADDR` | removed — never used in practice; `map --explore NAME` shows a function's real neighbours instead |
| `query.py --score-report` | removed — `research_wingman.py map DB --suspicious` |

Note that `research_wingman.py analyze` now **requires a scope** — the old
bare `main.py --database DB` maps to `research_wingman.py analyze DB --all`,
but `--top 100` (or `-f` on whatever `map --paths`/`--suspicious` turned up)
is almost always what you actually want.

Existing knowledge bases are upgraded in place on first open. Move an old
`knowledge_base.sqlite` and `call_graph.json` into `<database>.wingman/` to
keep your results — research-wingman will tell you if it spots them in the
current directory.

---

## Troubleshooting

**`No call graph yet`** — run `research_wingman.py map <db> --build` once.
Needs IDA, takes minutes, costs no LLM calls.

**`Ollama is not reachable`** — start it, or pass `--ollama-url`.

**`No Hex-Rays pseudocode available`** for many functions — the decompiler
isn't installed or doesn't support this architecture.

**`ask` says no semantic index** — `pip install faiss-cpu numpy` and
`ollama pull nomic-embed-text`. Without it you still get confidence ranking.

**Analysis seems to start over** — you're pointing at a different database
path. `research_wingman.py status <db>` shows which workspace is in use.

**Scripting `analyze` and it hangs** — always pass `--profile`
explicitly. Without it, it asks interactively before doing anything else; a
closed/empty stdin gets treated as "accept the default" and won't hang, but
anything else waiting to be answered will.

**`Database initialization failed` / `error 4`** — the `.i64` is already open
somewhere else: the IDA GUI, another `research_wingman.py`/idalib process, or
a leftover process from a run that didn't exit cleanly. IDA locks the
database exclusively while open, so a second opener always fails this way
rather than waiting or erroring more specifically. If you see loose
`.id0`/`.id1`/`.id2`/`.nam`/`.til` files sitting next to the `.i64`, that's
the unpacked working copy of an open (or not-yet-repacked) session — check
`Get-Process ida` (or `ps aux | grep ida` on Linux/macOS) for a still-running
process before assuming corruption. Close the other session (or wait for it
to exit) and retry; nothing needs to be deleted or repaired.

---

## Planned

- **Interactive review** — walk approved proposals one at a time with the
  evidence shown, approving or rejecting before `apply`.
- **Markdown call-tree export** from entry points, to feed document ranking
  against CVE corpora.
