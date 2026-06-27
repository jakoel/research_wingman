"""
Phase 5 storage layer — SQLite knowledge base.

Written by Phase 3 (LLM summarisation), read by Phase 4 (callee summary
injection + refinement) and Phase 6 (query).  The knowledge base is the
single source of truth for all per-function analysis results.
"""

from __future__ import annotations

import json
import sqlite3


class KnowledgeBase:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

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

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def upsert(self, entry: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO functions (
                address, old_name, new_name, confidence, summary,
                security_relevant, interesting_behaviors, callee_summaries_used,
                caller_count, score, phase3_done, phase4_refined
            ) VALUES (
                :address, :old_name, :new_name, :confidence, :summary,
                :security_relevant, :interesting_behaviors, :callee_summaries_used,
                :caller_count, :score, :phase3_done, :phase4_refined
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
                phase3_done           = excluded.phase3_done
            """,
            {
                "address":               str(entry["address"]),
                "old_name":              str(entry.get("old_name", "")),
                "new_name":              entry.get("new_name"),
                "confidence":            entry.get("confidence"),
                "summary":               entry.get("summary"),
                "security_relevant":     int(bool(entry.get("security_relevant", False))),
                "interesting_behaviors": json.dumps(
                    entry.get("interesting_behaviors") or []
                ),
                "callee_summaries_used": json.dumps(
                    entry.get("callee_summaries_used") or []
                ),
                "caller_count":          int(entry.get("caller_count", 0)),
                "score":                 float(entry.get("score", 0)),
                "phase3_done":           int(bool(entry.get("phase3_done", True))),
                "phase4_refined":        int(bool(entry.get("phase4_refined", False))),
            },
        )
        self._conn.commit()

    def mark_phase4_refined(self, address: str) -> None:
        self._conn.execute(
            "UPDATE functions SET phase4_refined = 1 WHERE address = ?",
            (str(address),),
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
                str(address),
            ),
        )
        self._conn.commit()

    def update_embedding_id(self, address: str, embedding_id: str) -> None:
        self._conn.execute(
            "UPDATE functions SET embedding_id = ? WHERE address = ?",
            (embedding_id, str(address)),
        )
        self._conn.commit()

    def upsert_edge(self, caller: str, callee: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO call_edges VALUES (?, ?)",
            (str(caller), str(callee)),
        )

    def flush(self) -> None:
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, address: int | str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM functions WHERE address = ?",
            (_addr_to_hex(address),),
        ).fetchone()
        return _row_to_dict(row) if row else None

    def is_phase3_done(self, address: int | str) -> bool:
        row = self._conn.execute(
            "SELECT phase3_done FROM functions WHERE address = ?",
            (_addr_to_hex(address),),
        ).fetchone()
        return bool(row and row["phase3_done"])

    def get_callee_summaries(self, callee_addresses: list[int]) -> list[dict]:
        """Retrieve KB entries for a list of callee addresses (for prompt injection)."""
        if not callee_addresses:
            return []
        hex_addrs = [_addr_to_hex(a) for a in callee_addresses]
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

    def get_callers_in_kb(
        self, address: str, graph_callers: list[int]
    ) -> list[dict]:
        """Return KB entries for callers that have already been analyzed."""
        if not graph_callers:
            return []
        hex_addrs = [_addr_to_hex(a) for a in graph_callers]
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
        """Functions eligible for top-down refinement (Phase 4)."""
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
        """All entries with a summary, for FAISS indexing."""
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE summary IS NOT NULL AND summary != ''"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_all_phase3_done(self) -> list[dict]:
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
        """
        Return ancestors (callers) and descendants (callees) of address
        up to `depth` hops, for call-chain display in Phase 6.
        """
        visited = set()
        result = []
        self._walk_chain(address, depth, visited, result)
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
    if s.startswith("0x") or s.startswith("0X"):
        return s.upper().replace("0X", "0x")
    # Decimal integer stored as string
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
    d["security_relevant"] = bool(d.get("security_relevant"))
    return d
