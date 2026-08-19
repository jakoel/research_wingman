"""
SQLite knowledge base — the single source of truth for all analysis state.

Every fact about a function lives in one row: the LLM's proposal, whether it
was accepted or rejected and why, and whether it has been written into the IDA
database. There is no separate checkpoint file and no review file that has to
be kept in sync — resume, review and apply all read this table.

Row lifecycle
-------------
    analyzed=0                     never seen, or the last attempt errored
    analyzed=1, status='rejected'  seen and ruled out (won't be retried)
    analyzed=1, status='approved'  has a usable rename proposal
    applied=1                      the rename is in the IDA database

The `phase3_done` / `phase4_refined` column names are retained for
compatibility with knowledge bases built by earlier versions; the methods
below use the clearer `analyzed` / `refined` vocabulary.
"""

from __future__ import annotations

import json
import sqlite3
import time

# Columns added after the original schema. Applied to existing databases with
# ALTER TABLE so an old knowledge base keeps working.
_ADDED_COLUMNS = {
    "status":           "TEXT",
    "risk":             "TEXT",
    "reason":           "TEXT",
    "rejection_reason": "TEXT",
    "applied":          "INTEGER DEFAULT 0",
    "applied_name":     "TEXT",
    "analyzed_at":      "TEXT",
    # What num_ctx a function's analyze call actually used and how big its
    # prompt was -- see llm_client.OllamaClient.analyze_sized. Recorded per
    # row (not just printed) so a specific function's analysis can be audited
    # for truncation risk after the fact, not only during the run itself.
    "num_ctx_used":     "INTEGER",
    "prompt_chars":     "INTEGER",
    # Set when this function's real decompiled body exceeded
    # analysis.max_pseudocode_lines -- the model's prompt embedded a
    # truncation marker, but nothing surfaced that to the operator. Recorded
    # per row so a run can be audited for "did any function's real content
    # get silently cut" after the fact, not just via the live console
    # warning.
    "pseudocode_truncated": "INTEGER DEFAULT 0",
    # Structural family key -- sha256[:16] of family.normalize_pseudocode()'s
    # output, set when the body has enough real content to be meaningful
    # (family.is_hashable). NULL for functions never analyzed, functions
    # whose body was too trivial to hash, or rows written before this column
    # existed. See family.py's module docstring and get_family_members below.
    "body_hash": "TEXT",
}

STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"


class KnowledgeBase:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        self._migrate()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS functions (
                address               TEXT PRIMARY KEY,
                old_name              TEXT NOT NULL,
                new_name              TEXT,
                confidence            REAL,
                summary               TEXT,
                security_relevant     INTEGER DEFAULT 0,
                interesting_behaviors TEXT,
                callee_summaries_used TEXT,
                caller_count          INTEGER DEFAULT 0,
                score                 REAL    DEFAULT 0,
                phase3_done           INTEGER DEFAULT 0,
                phase4_refined        INTEGER DEFAULT 0,
                embedding_id          TEXT
            );

            CREATE TABLE IF NOT EXISTS call_edges (
                caller_address  TEXT NOT NULL,
                callee_address  TEXT NOT NULL,
                PRIMARY KEY (caller_address, callee_address)
            );

            CREATE TABLE IF NOT EXISTS meta (
                key    TEXT PRIMARY KEY,
                value  TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_security
                ON functions(security_relevant);
            CREATE INDEX IF NOT EXISTS idx_confidence
                ON functions(confidence);
            CREATE INDEX IF NOT EXISTS idx_phase3
                ON functions(phase3_done);
        """)
        self._conn.commit()

    def _migrate(self) -> None:
        existing = {
            row[1] for row in self._conn.execute("PRAGMA table_info(functions)")
        }
        added = []
        for name, decl in _ADDED_COLUMNS.items():
            if name not in existing:
                self._conn.execute(
                    f"ALTER TABLE functions ADD COLUMN {name} {decl}"
                )
                added.append(name)

        # A knowledge base from before `status` existed encoded the same
        # decision implicitly: an analyzed row either got a new name or it
        # didn't. Backfill it, or those rows would be invisible to `apply`.
        if "status" in added:
            self._conn.execute(
                "UPDATE functions SET status = CASE "
                "  WHEN new_name IS NOT NULL AND new_name != '' THEN ? ELSE ? END "
                "WHERE phase3_done = 1 AND status IS NULL",
                (STATUS_APPROVED, STATUS_REJECTED),
            )
            n = self._conn.total_changes
            if n:
                print(f"[wingman] Migrated {n} existing knowledge base row(s).")

        # `status`/`applied` are migration-added columns (see _ADDED_COLUMNS
        # above), so this index can't live in _init_schema's CREATE TABLE
        # block -- it has to run after the ALTER TABLEs above have actually
        # added them. Matches the real hot queries (get_approved_unapplied,
        # get_unrefined, stats()), which all filter on these two columns;
        # `idx_score` (removed) indexed a column nothing in kb.py ever
        # filters or sorts on.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status_applied "
            "ON functions(status, applied)"
        )
        # body_hash is looked up once per analyzed function (get_family_members/
        # count_family_members, called from pipeline._run_plan) -- a real hot
        # query at a few thousand functions per binary, not a cold one.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_body_hash "
            "ON functions(body_hash)"
        )

        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, entry: dict) -> None:
        """
        Insert or update the row for one function. This is the only write path
        used during analysis — approvals, rejections and errors all land here.

        If this address was already applied, and the fresh result is a
        genuine confidence improvement (strictly higher, and approved, not
        just re-analyzed into a rejection), `applied` is cleared so `apply()`
        reconsiders it. A same-or-lower-confidence re-analysis doesn't touch
        `applied` at all, so a good already-applied result is never churned
        by re-running analysis on it. See `RenamePolicy.can_rename` for the
        matching apply-time check (only ever overwrites the tool's own prior
        name, never a genuine analyst name).
        """
        addr_hex = addr_to_hex(entry["address"])
        reset_applied = False
        if entry.get("status") == STATUS_APPROVED and entry.get("confidence") is not None:
            prior = self._conn.execute(
                "SELECT applied, confidence FROM functions WHERE address = ?",
                (addr_hex,),
            ).fetchone()
            if prior and prior["applied"]:
                old_confidence = prior["confidence"] or 0.0
                if float(entry["confidence"]) > float(old_confidence):
                    reset_applied = True

        params = {
            "address":               addr_hex,
            "old_name":              str(entry.get("old_name", "")),
            "new_name":              entry.get("new_name"),
            "confidence":            entry.get("confidence"),
            "summary":               entry.get("summary"),
            "security_relevant":     int(bool(entry.get("security_relevant", False))),
            "interesting_behaviors": json.dumps(entry.get("interesting_behaviors") or []),
            "callee_summaries_used": json.dumps(entry.get("callee_summaries_used") or []),
            "caller_count":          int(entry.get("caller_count", 0)),
            "score":                 float(entry.get("score", 0)),
            "phase3_done":           int(bool(entry.get("analyzed", True))),
            "phase4_refined":        int(bool(entry.get("refined", False))),
            "status":                entry.get("status"),
            "risk":                  entry.get("risk"),
            "reason":                entry.get("reason"),
            "rejection_reason":      entry.get("rejection_reason") or "",
            "analyzed_at":           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "num_ctx_used":          entry.get("num_ctx_used"),
            "prompt_chars":          entry.get("prompt_chars"),
            "pseudocode_truncated":  int(bool(entry.get("pseudocode_truncated", False))),
            "body_hash":             entry.get("body_hash"),
        }
        self._conn.execute(
            """
            INSERT INTO functions (
                address, old_name, new_name, confidence, summary,
                security_relevant, interesting_behaviors, callee_summaries_used,
                caller_count, score, phase3_done, phase4_refined,
                status, risk, reason, rejection_reason, analyzed_at,
                num_ctx_used, prompt_chars, pseudocode_truncated, body_hash
            ) VALUES (
                :address, :old_name, :new_name, :confidence, :summary,
                :security_relevant, :interesting_behaviors, :callee_summaries_used,
                :caller_count, :score, :phase3_done, :phase4_refined,
                :status, :risk, :reason, :rejection_reason, :analyzed_at,
                :num_ctx_used, :prompt_chars, :pseudocode_truncated, :body_hash
            )
            ON CONFLICT(address) DO UPDATE SET
                old_name              = excluded.old_name,
                new_name              = excluded.new_name,
                confidence            = excluded.confidence,
                summary               = excluded.summary,
                security_relevant     = excluded.security_relevant,
                interesting_behaviors = excluded.interesting_behaviors,
                callee_summaries_used = excluded.callee_summaries_used,
                caller_count          = excluded.caller_count,
                score                 = excluded.score,
                phase3_done           = excluded.phase3_done,
                phase4_refined        = excluded.phase4_refined,
                status                = excluded.status,
                risk                  = excluded.risk,
                reason                = excluded.reason,
                rejection_reason      = excluded.rejection_reason,
                analyzed_at           = excluded.analyzed_at,
                num_ctx_used          = excluded.num_ctx_used,
                prompt_chars          = excluded.prompt_chars,
                pseudocode_truncated  = excluded.pseudocode_truncated,
                body_hash             = excluded.body_hash
            """,
            params,
        )
        if reset_applied:
            self._conn.execute(
                "UPDATE functions SET applied = 0 WHERE address = ?", (addr_hex,)
            )
        self._conn.commit()

    def mark_refined(self, address: str) -> None:
        self._conn.execute(
            "UPDATE functions SET phase4_refined = 1 WHERE address = ?",
            (addr_to_hex(address),),
        )
        self._conn.commit()

    def update_after_refinement(
        self,
        address: str,
        new_name: str | None,
        summary: str,
        confidence: float,
        security_relevant: bool,
        interesting_behaviors: list[str],
    ) -> None:
        """
        Apply a refinement result. The refiner only calls this when the LLM
        reported `changed=true`, so this is always a genuine improvement.

        `applied` is cleared here for the same reason `record()` clears it on
        a confidence upgrade: if this function had already been written into
        the database, the refined name/summary would otherwise be stranded in
        the KB and never reach IDA. Clearing it makes the row pending again so
        the next `apply` picks up the improvement. If the refined name turns
        out identical to what's already in the database, `apply`'s same-name
        no-op path handles it harmlessly. `applied_name` is deliberately left
        intact so `RenamePolicy.can_rename` still recognises the database's
        current name as our own prior write, not an analyst's.
        """
        self._conn.execute(
            """
            UPDATE functions SET
                new_name              = ?,
                summary               = ?,
                confidence            = ?,
                security_relevant     = ?,
                interesting_behaviors = ?,
                phase4_refined        = 1,
                applied               = 0
            WHERE address = ?
            """,
            (
                new_name,
                summary,
                confidence,
                int(security_relevant),
                json.dumps(interesting_behaviors),
                addr_to_hex(address),
            ),
        )
        self._conn.commit()

    def mark_applied(self, address: str, applied_name: str) -> None:
        self._conn.execute(
            "UPDATE functions SET applied = 1, applied_name = ? WHERE address = ?",
            (applied_name, addr_to_hex(address)),
        )
        self._conn.commit()

    def upsert_edge(self, caller: str, callee: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO call_edges VALUES (?, ?)",
            (addr_to_hex(caller), addr_to_hex(callee)),
        )

    def flush(self) -> None:
        self._conn.commit()

    # ---- meta ---------------------------------------------------------

    def get_meta(self, key: str, default=None):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value) -> None:
        self._conn.execute(
            "INSERT INTO meta VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        self._conn.commit()

    def seconds_per_call(self) -> float | None:
        """Observed average LLM latency, so cost quotes reflect this setup."""
        raw = self.get_meta("seconds_per_call")
        try:
            v = float(raw)
            return v if v > 0 else None
        except (TypeError, ValueError):
            return None

    def record_timing(self, calls: int, elapsed: float) -> None:
        """Fold this run's latency into a running average."""
        if calls <= 0 or elapsed <= 0:
            return
        observed = elapsed / calls
        prior = self.seconds_per_call()
        blended = observed if prior is None else (prior * 0.6 + observed * 0.4)
        # Keep enough precision that a fast setup doesn't round to zero and
        # lose the measurement entirely.
        self.set_meta("seconds_per_call", round(blended, 4))

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, address: int | str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM functions WHERE address = ?",
            (addr_to_hex(address),),
        ).fetchone()
        return _row_to_dict(row) if row else None

    def is_analyzed(self, address: int | str) -> bool:
        row = self._conn.execute(
            "SELECT phase3_done FROM functions WHERE address = ?",
            (addr_to_hex(address),),
        ).fetchone()
        return bool(row and row["phase3_done"])

    def stats(self) -> dict:
        """Counts used by `research_wingman.py status` and the end-of-run summary."""
        def _one(sql: str, *args) -> int:
            return self._conn.execute(sql, args).fetchone()[0]

        return {
            "analyzed": _one("SELECT COUNT(*) FROM functions WHERE phase3_done = 1"),
            "approved": _one(
                "SELECT COUNT(*) FROM functions WHERE status = ?", STATUS_APPROVED
            ),
            "rejected": _one(
                "SELECT COUNT(*) FROM functions WHERE status = ?", STATUS_REJECTED
            ),
            "applied": _one("SELECT COUNT(*) FROM functions WHERE applied = 1"),
            # Matches get_approved_unapplied()'s predicate exactly (minus its
            # min_confidence param, which defaults to 0.0 there anyway) --
            # they used to diverge (this one omitted the new_name check),
            # which could make this count claim a row is pending-apply that
            # apply() would actually skip.
            "pending_apply": _one(
                "SELECT COUNT(*) FROM functions "
                "WHERE status = ? AND COALESCE(applied, 0) = 0 "
                "AND new_name IS NOT NULL AND new_name != ''",
                STATUS_APPROVED,
            ),
            "refined": _one("SELECT COUNT(*) FROM functions WHERE phase4_refined = 1"),
            "security": _one(
                "SELECT COUNT(*) FROM functions WHERE security_relevant = 1"
            ),
            "with_summary": _one(
                "SELECT COUNT(*) FROM functions "
                "WHERE summary IS NOT NULL AND summary != ''"
            ),
            "pseudocode_truncated": _one(
                "SELECT COUNT(*) FROM functions WHERE pseudocode_truncated = 1"
            ),
        }

    def get_approved_unapplied(self, min_confidence: float = 0.0) -> list[dict]:
        """Rows ready to be written into the IDA database, best first."""
        rows = self._conn.execute(
            """
            SELECT * FROM functions
            WHERE status = ?
              AND COALESCE(applied, 0) = 0
              AND new_name IS NOT NULL AND new_name != ''
              AND COALESCE(confidence, 0) >= ?
            ORDER BY confidence DESC
            """,
            (STATUS_APPROVED, min_confidence),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_all(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM functions ORDER BY address"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_callee_summaries(self, callee_addresses: list[int]) -> list[dict]:
        """KB entries for a list of callee addresses (for prompt injection)."""
        return self._by_addresses(callee_addresses)

    def get_callers_in_kb(
        self, address: str, graph_callers: list[int]
    ) -> list[dict]:
        """KB entries for callers that have already been analyzed."""
        return self._by_addresses(graph_callers)

    def get_family_members(
        self, body_hash: str | None, exclude_address: str, limit: int = 6
    ) -> list[dict]:
        """Other KB rows sharing this body_hash -- see family.py. Whole-KB,
        not scoped to the current run's candidates, so family membership
        correctly accumulates across multiple `analyze` runs over time (a
        `-f` run on 2 functions today still sees a sibling analyzed in a
        `--all` run last week). Capped at `limit`: unlike `_by_addresses`'s
        deliberately-uncapped direct-neighbour listing (real call-graph
        evidence), a family signal's value is "you're one of many" plus a
        few examples, not an exhaustive dump of a 40+ member cluster into
        every sibling's prompt -- see count_family_members for the true
        total. Approved-with-a-real-name entries ordered first (the useful
        examples), then confidence, then address for determinism."""
        if not body_hash:
            return []
        rows = self._conn.execute(
            """
            SELECT * FROM functions
            WHERE body_hash = ? AND address != ? AND phase3_done = 1
            ORDER BY (status = ?) DESC, confidence DESC, address ASC
            LIMIT ?
            """,
            (body_hash, addr_to_hex(exclude_address), STATUS_APPROVED, limit),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def count_family_members(self, body_hash: str | None, exclude_address: str) -> int:
        """True (uncapped) sibling count for `body_hash` -- the count itself
        is signal ("41 structurally identical bodies exist") independent of
        how many examples get_family_members actually returns."""
        if not body_hash:
            return 0
        row = self._conn.execute(
            "SELECT COUNT(*) FROM functions WHERE body_hash = ? AND address != ? "
            "AND phase3_done = 1",
            (body_hash, addr_to_hex(exclude_address)),
        ).fetchone()
        return row[0] if row else 0

    def _by_addresses(self, addresses: list[int]) -> list[dict]:
        """All matching KB rows, security-relevant and higher-confidence
        first -- callers cap this list before injecting it into a prompt
        (see prompts._render_kb_neighbours), so a caller/callee neighbour
        actually worth showing must not lose to arbitrary row order when a
        function has more analyzed neighbours than fit in the cap (a real
        orchestrator/dispatcher fan-out case, confirmed 2026-08-16: up to 64
        already-summarized callees on a single function with no ordering)."""
        if not addresses:
            return []
        hex_addrs = [addr_to_hex(a) for a in addresses]
        placeholders = ",".join("?" * len(hex_addrs))
        rows = self._conn.execute(
            f"""
            SELECT * FROM functions
            WHERE address IN ({placeholders})
              AND phase3_done = 1
              AND summary IS NOT NULL
            ORDER BY security_relevant DESC, confidence DESC, address ASC
            """,
            hex_addrs,
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_unrefined(self, skip_confidence: float = 0.85) -> list[dict]:
        """
        Functions eligible for the top-down refinement pass.

        Only approved proposals -- a rejected row (low confidence, high risk,
        vague name, ...) was deliberately kept out of the rename set, and
        refinement writing a real new_name into it without revisiting *why*
        it was rejected would silently undo that decision (status stays
        'rejected' so `apply` still won't use it, but anything reading the KB
        directly, e.g. the map explore view, would show a name that was never
        actually approved).

        `wrapper_*` entries bypass the confidence skip entirely: their high
        confidence (set deliberately by the analyze prompt -- see
        prompts.py) reflects certainty about a STRUCTURAL fact ("this body is
        just a forward/constant return"), not about the SEMANTIC role that
        confidence normally gates on. A trivial one-line body can't reveal
        that role at all -- only caller usage can (see the refiner's
        call-site injection below) -- so these are exactly the entries worth
        a second look regardless of how confident the structural read was.
        """
        rows = self._conn.execute(
            """
            SELECT * FROM functions
            WHERE phase3_done = 1
              AND phase4_refined = 0
              AND status = ?
              AND (
                    confidence IS NULL
                    OR confidence < ?
                    OR new_name LIKE 'wrapper\\_%' ESCAPE '\\'
                  )
            """,
            (STATUS_APPROVED, skip_confidence),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_pseudocode_truncated(self) -> list[dict]:
        """Functions whose real decompiled body exceeded
        analysis.max_pseudocode_lines -- what a run actually cut short, so a
        user can go raise the cap, inspect the function directly in IDA, or
        re-run just these with a higher --limit-equivalent override."""
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE pseudocode_truncated = 1 ORDER BY address"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_all_for_embedding(self) -> list[dict]:
        """All entries with a summary, for semantic indexing."""
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE summary IS NOT NULL AND summary != ''"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_all_analyzed(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE phase3_done = 1"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def search_by_security(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM functions
            WHERE security_relevant = 1 AND phase3_done = 1
            ORDER BY confidence DESC
            """
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def addr_to_hex(addr: int | str) -> str:
    """Normalise an address to the canonical '0xABCD' hex string used as this
    table's PK -- and, since every other module that formats an address needs
    the exact same canonical form to key into the KB correctly, the one place
    that formatting is allowed to live. Public (not `_`-prefixed) for that
    reason: `pipeline`, `mapview`, `refiner`, and `idapro_client` all import
    it instead of reimplementing `f"0x{addr:X}"` locally."""
    if isinstance(addr, int):
        return f"0x{addr:X}"
    s = str(addr).strip()
    if s.lower().startswith("0x"):
        return "0x" + s[2:].upper()
    try:
        # Addresses in this codebase are always hex -- a bare digit string
        # (e.g. a user typing `-f 1B0111C10` without the 0x prefix) must
        # be parsed as hex, not decimal, or it silently keys into the wrong
        # row (confirmed real: "1000" meaning 0x1000 was misread as decimal
        # 1000 -> "0x3E8").
        return f"0x{int(s, 16):X}"
    except ValueError:
        return s


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for key in ("interesting_behaviors", "callee_summaries_used"):
        if isinstance(d.get(key), str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                d[key] = []
    d["security_relevant"] = bool(d.get("security_relevant"))
    d["applied"] = bool(d.get("applied"))
    d["analyzed"] = bool(d.get("phase3_done"))
    d["refined"] = bool(d.get("phase4_refined"))
    return d
