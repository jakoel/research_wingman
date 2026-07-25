# rh — a reverse engineering copilot

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
So `rh` splits into two halves:

- **`map`** — instant, no LLM. Entry points, imports, strings, call paths,
  which functions touch `memcpy` with attacker-controlled data. This answers
  most questions on its own.
- **`analyze`** — costs LLM calls, so it always requires an explicit scope and
  quotes the cost before spending it. There is no accidental overnight run.

---

## Just run it

```bash
python rh.py target.i64
```

That's the whole interface. It opens the database once, keeps it open for the
session, and everything is a menu choice — there are no flags to remember.

Run `python rh.py` with no arguments and it finds a `.i64` in the current
directory and opens that.

```
────────────────────────────────────────────────────────────────────────
  target.i64   graph: 45210 functions   6.2s per function
  analyzed: 128   security-flagged: 19   ready to apply: 96
────────────────────────────────────────────────────────────────────────
  MAP — instant, no LLM
    1  Overview            size, entry points, imports, landmarks
    2  Suspicious          ranked by score
    3  Find                by name, string or imported API
    4  Explore             one function and its neighbours

  ANALYZE — uses the LLM, cost quoted first
    5  One function
    6  Around a function   its callees and/or callers
    7  A call path         entry -> sink, or between two functions
    8  Top N suspicious
    9  Everything          (the overnight run)

  RESULTS
    a  Ask     s  Status     p  Apply to database     e  Export
    m  Maintenance           q  Quit
```

`m` covers rebuilding the call graph, rebuilding the search index, switching
model, and deleting results — so you never have to leave the session to do
housekeeping.

Options 1–4 cost nothing. Options 5–9 show you something like this first, and
wait:

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

- **`analyze` never modifies the database.** It only reads.
- **`apply` never calls the LLM.** It only writes what `analyze` already decided.

---

## A worked example

You're looking for a parsing bug in a network service. This is the same flow
the menu walks you through — shown as commands so each step is explicit.

```bash
# 1. Build the map once. Needs IDA, takes minutes, no LLM calls.
#    (The session offers to do this for you on first open.)
python rh.py map target.i64 --build

# 2. Where does network data arrive and where does it end up?
python rh.py map target.i64 --paths
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
# 3. That's the interesting path. Analyze exactly it — 7 functions, not 45,000.
python rh.py analyze target.i64 --to-sinks

# 4. Or go straight at the header parser you spotted.
python rh.py map target.i64 --find "Content-Length"
python rh.py analyze target.i64 --callees sub_401400 --depth 2

# 5. Read the results, then write them into the database.
python rh.py ask target.i64 "unchecked length used in a copy"
python rh.py apply target.i64 --dry-run
python rh.py apply target.i64
```

---

## Commands

You don't need these — the session covers all of it. They exist for scripting
and for when you already know exactly what you want.

### `map` — free, instant, no LLM

```bash
python rh.py map target.i64                      # overview
python rh.py map target.i64 --build              # build/refresh the graph (needs IDA)
python rh.py map target.i64 --suspicious 25      # ranked by score
python rh.py map target.i64 --find "recv"        # names, strings, imported APIs
python rh.py map target.i64 --explore sub_401400 # one function in detail
python rh.py map target.i64 --paths              # entry point -> memory sink
```

`--find` searches referenced strings and imports too, because they're cached in
the graph. Once the graph is built, none of this needs IDA open.

The ranking behind `--suspicious` is the xref heuristic: functions called from
1–3 places are unique code paths where bugs live; functions called from 50+
places are utilities. Add bonuses for calling a memory sink and for being
reachable from an input source.

### `analyze` — scoped, priced

A scope is **required**:

| Scope | What it selects |
|---|---|
| `-f NAME...` | Exactly these functions (name or `0xADDR`) |
| `--callees NAME` | It and what it calls, `--depth` hops down |
| `--callers NAME` | It and what calls it, `--depth` hops up |
| `--around NAME` | Both directions |
| `--between A B` | Every function on the call paths from A to B |
| `--to-sinks` | Paths from entry points down to memory sinks |
| `--top N` | The N highest-scoring unnamed functions |
| `--all` | Every auto-named function (the overnight run) |

Modifiers: `--depth N` (default 2) · `--limit N` LLM calls · `--redo` to
re-analyze finished functions · `-y` to skip the cost prompt · `--start NAME`
to root `--to-sinks` somewhere specific.

Analysis runs leaves-first, so by the time a caller is analyzed its callees'
summaries are already in the prompt. Interrupt any run and rerun it — finished
functions are skipped.

### `apply`, `ask`, `status`, `export`

```bash
python rh.py apply  target.i64 --dry-run     # exactly what would change
python rh.py apply  target.i64               # write renames + IDA comments
python rh.py ask    target.i64 "question"    # semantic search
python rh.py ask    target.i64 --report      # every security-flagged function
python rh.py ask    target.i64 --chain 0x401000
python rh.py status target.i64
python rh.py export target.i64               # review.json
```

`apply` re-checks each function's current name at write time, so anything
you've renamed yourself is left alone. Applied rows are marked — running it
twice is harmless.

`ask` builds its semantic index automatically when it's missing or stale.
`ask` and `status` don't open the database at all.

---

## Where state lives

```
/malware/sample.i64
/malware/sample.i64.rh/
    knowledge_base.sqlite     every result — the single source of truth
    call_graph.json           cached call graph
    kb_vectors.faiss (.map)   semantic search index
    audit.jsonl               append-only log of every action
    review.json               written by `rh export`, on demand
```

State follows the binary, not your shell, so you can never silently start over
and re-spend LLM calls.

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
ollama pull codellama:13b-instruct
ollama pull nomic-embed-text        # only for semantic search
```

Only `analyze`, `apply`, `menu` and `map --build` need IDA. Everything else
runs off the workspace.

---

## Configure

`llm_renamer/config.json` is the whole user-facing config:

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

Scoring weights, sink lists, name blacklists and prompt sizing live in
`llm_renamer/config.py` as defaults. Add any of them here to override.

---

## Rename policy

- Only auto-generated names are eligible: `sub_*`, `j_*`, `nullsub_*`,
  `locret_*`, `loc_*`. Analysis can target anything; `apply` still refuses to
  overwrite an analyst's name.
- Rejected if confidence is below threshold, risk is `high`, or the name is
  vague, illegal, digit-leading, or over 64 characters.
- Collisions get `_2`, `_3`, … up to nine variants.
- Rejections are recorded so they aren't retried. LLM *errors* are not, so
  those do get retried.

---

## Project layout

```
rh.py                    the CLI
llm_renamer/
  menu.py                interactive session
  navigate.py            graph traversal: paths, neighbourhoods, search
  mapview.py             map rendering
  pipeline.py            analyze() and apply() — the two IDA-facing operations
  ask.py                 semantic search, reports, status
  workspace.py           where state lives for a database
  kb.py                  SQLite knowledge base (single source of truth)
  call_graph.py          call graph construction and caching
  scorer.py              scoring and bottom-up ordering
  idapro_client.py       IDA context extraction
  llm_client.py          Ollama HTTP client (stdlib only)
  prompts.py             system prompt and per-function prompt builder
  validator.py           output validation and snake_case sanitization
  renamer.py             the only place that calls idc.set_name
  refiner.py             top-down refinement pass
  embedder.py            semantic index
  export.py              review JSON writer
  audit.py               append-only JSONL log
  config.py / config.json
main.py                  shim pointing at the replacements
ARCHITECTURE.md          design reference
```

---

## Upgrading from `main.py` / `query.py`

Both are gone. Run `python main.py` for a mapping table. Note that
`rh analyze` now **requires a scope** — the old bare `main.py --database DB`
maps to `rh analyze DB --all`, but `--top 100` or `--to-sinks` is almost always
what you actually want.

Existing knowledge bases are upgraded in place on first open. Move an old
`knowledge_base.sqlite` and `call_graph.json` into `<database>.rh/` to keep your
results — `rh` will tell you if it spots them in the current directory.

---

## Troubleshooting

**`No call graph yet`** — run `rh map <db> --build` once. Needs IDA, takes
minutes, costs no LLM calls.

**`Ollama is not reachable`** — start it, or pass `--ollama-url`.

**`No Hex-Rays pseudocode available`** for many functions — the decompiler
isn't installed or doesn't support this architecture.

**`ask` says no semantic index** — `pip install faiss-cpu numpy` and
`ollama pull nomic-embed-text`. Without it you still get confidence ranking.

**Analysis seems to start over** — you're pointing at a different database
path. `rh status <db>` shows which workspace is in use.

---

## Planned

- **Interactive review** — walk approved proposals one at a time with the
  evidence shown, approving or rejecting before `apply`.
- **Markdown call-tree export** from entry points, to feed document ranking
  against CVE corpora.
