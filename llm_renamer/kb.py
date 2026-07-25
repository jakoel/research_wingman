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
    "evidence":         "TEXT",
    "rejection_reason": "TEXT",
    "applied":          "INTEGER DEFAULT 0",
    "applied_name":     "TEXT",
    "analyzed_at":      "TEXT",
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
            CREATE INDEX IF NOT EXISTS idx_score
                ON functions(score DESC);
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
                print(f"[rh] Migrated {n} existing knowledge base row(s).")

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
        """
        params = {
            "address":               _addr_to_hex(entry["address"]),
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
            "evidence":              json.dumps(entry.get("evidence") or {}),
            "rejection_reason":      entry.get("rejection_reason") or "",
            "analyzed_at":           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._conn.execute(
            """
            INSERT INTO functions (
                address, old_name, new_name, confidence, summary,
                security_relevant, interesting_behaviors, callee_summaries_used,
                caller_count, score, phase3_done, phase4_refined,
                status, risk, reason, evidence, rejection_reason, analyzed_at
            ) VALUES (
                :address, :old_name, :new_name, :confidence, :summary,
                :security_relevant, :interesting_behaviors, :callee_summaries_used,
                :caller_count, :score, :phase3_done, :phase4_refined,
                :status, :risk, :reason, :evidence, :rejection_reason, :analyzed_at
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
                status                = excluded.status,
                risk                  = excluded.risk,
                reason                = excluded.reason,
                evidence              = excluded.evidence,
                rejection_reason      = excluded.rejection_reason,
                analyzed_at           = excluded.analyzed_at
            """,
            params,
        )
        self._conn.commit()

    def mark_refined(self, address: str) -> None:
        self._conn.execute(
            "UPDATE functions SET phase4_refined = 1 WHERE address = ?",
            (_addr_to_hex(address),),
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
        self._conn.execute(
            """
            UPDATE functions SET
                new_name              = ?,
                summary               = ?,
                confidence            = ?,
                security_relevant     = ?,
                interesting_behaviors = ?,
                phase4_refined        = 1
            WHERE address = ?
            """,
            (
                new_name,
                summary,
                confidence,
                int(security_relevant),
                json.dumps(interesting_behaviors),
                _addr_to_hex(address),
            ),
        )
        self._conn.commit()

    def mark_applied(self, address: str, applied_name: str) -> None:
        self._conn.execute(
            "UPDATE functions SET applied = 1, applied_name = ? WHERE address = ?",
            (applied_name, _addr_to_hex(address)),
        )
        self._conn.commit()

    def update_embedding_id(self, address: str, embedding_id: str) -> None:
        self._conn.execute(
            "UPDATE functions SET embedding_id = ? WHERE address = ?",
            (embedding_id, _addr_to_hex(address)),
        )
        self._conn.commit()

    def upsert_edge(self, caller: str, callee: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO call_edges VALUES (?, ?)",
            (_addr_to_hex(caller), _addr_to_hex(callee)),
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

    def reset(self) -> int:
        """Drop all analysis results. Returns the number of rows removed."""
        n = self._conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        self._conn.executescript(
            "DELETE FROM functions; DELETE FROM call_edges;"
        )
        self._conn.commit()
        return n

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, address: int | str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM functions WHERE address = ?",
            (_addr_to_hex(address),),
        ).fetchone()
        return _row_to_dict(row) if row else None

    def is_analyzed(self, address: int | str) -> bool:
        row = self._conn.execute(
            "SELECT phase3_done FROM functions WHERE address = ?",
            (_addr_to_hex(address),),
        ).fetchone()
        return bool(row and row["phase3_done"])

    def count_analyzed(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM functions WHERE phase3_done = 1"
        ).fetchone()[0]

    def stats(self) -> dict:
        """Counts used by `rh status` and the end-of-run summary."""
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
            "pending_apply": _one(
                "SELECT COUNT(*) FROM functions "
                "WHERE status = ? AND COALESCE(applied, 0) = 0",
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

    def _by_addresses(self, addresses: list[int]) -> list[dict]:
        if not addresses:
            return []
        hex_addrs = [_addr_to_hex(a) for a in addresses]
        placeholders = ",".join("?" * len(hex_addrs))
        rows = self._conn.execute(
            f"""
            SELECT * FROM functions
            WHERE address IN ({placeholders})
              AND phase3_done = 1
              AND summary IS NOT NULL
            """,
            hex_addrs,
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_unrefined(self, skip_confidence: float = 0.85) -> list[dict]:
        """Functions eligible for the top-down refinement pass."""
        rows = self._conn.execute(
            """
            SELECT * FROM functions
            WHERE phase3_done = 1
              AND phase4_refined = 0
              AND (confidence IS NULL OR confidence < ?)
            """,
            (skip_confidence,),
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

    def get_call_chain(self, address: str, depth: int = 4) -> list[dict]:
        """Descendants of address up to `depth` hops, for call-chain display."""
        visited: set[str] = set()
        result: list[dict] = []
        self._walk_chain(_addr_to_hex(address), depth, visited, result)
        return result

    def _walk_chain(
        self,
        address: str,
        depth: int,
        visited: set[str],
        result: list[dict],
    ) -> None:
        if depth < 0 or address in visited:
            return
        visited.add(address)
        entry = self.get(address)
        if entry:
            result.append(entry)
        rows = self._conn.execute(
            "SELECT callee_address FROM call_edges WHERE caller_address = ?",
            (address,),
        ).fetchall()
        for row in rows:
            self._walk_chain(row[0], depth - 1, visited, result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _addr_to_hex(addr: int | str) -> str:
    """Normalise an address to the canonical '0xABCD' hex string used as the PK."""
    if isinstance(addr, int):
        return f"0x{addr:X}"
    s = str(addr).strip()
    if s.lower().startswith("0x"):
        return "0x" + s[2:].upper()
    try:
        return f"0x{int(s):X}"
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
    if isinstance(d.get("evidence"), str):
        try:
            d["evidence"] = json.loads(d["evidence"])
        except (json.JSONDecodeError, TypeError):
            d["evidence"] = {}
    d["security_relevant"] = bool(d.get("security_relevant"))
    d["applied"] = bool(d.get("applied"))
    d["analyzed"] = bool(d.get("phase3_done"))
    d["refined"] = bool(d.get("phase4_refined"))
    return d
