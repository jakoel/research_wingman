"""
idasql HTTP client for llm_renamer.

Talks to a running idasql server (idasql -s binary.i64 --http 8081) via
POST /query with SQL statements, and returns rows as list[dict].

Response format auto-detection:
  idasql may return:
    (a) a JSON array of row objects  [{"name": "sub_401000", "address": 4198400}, ...]
    (b) a columnar JSON object        {"columns": ["name","address"], "rows": [[...], ...]}
    (c) plain text / TSV              (last resort: each line becomes {"line": "..."})
"""

import json
import urllib.request
import urllib.error


class IdaSQLError(Exception):
    pass


class IdaSQLClient:
    def __init__(self, config: dict):
        self._url = config["idasql"]["url"].rstrip("/")
        self._timeout = int(config["idasql"]["timeout_seconds"])

    # ------------------------------------------------------------------
    # Core query interface
    # ------------------------------------------------------------------

    def query(self, sql: str) -> list[dict]:
        """
        Execute sql against idasql and return rows as a list of dicts.
        Raises IdaSQLError on network failure or unparseable response.
        """
        body = self._post(sql)
        return self._parse(body, sql)

    def query_one(self, sql: str, column: str):
        """Return the value of `column` from the first row, or None."""
        rows = self.query(sql)
        if rows and column in rows[0]:
            return rows[0][column]
        if rows:
            # Take first value regardless of column name
            return next(iter(rows[0].values()), None)
        return None

    def execute(self, sql: str) -> bool:
        """
        Execute a write statement (UPDATE / INSERT).
        Returns True if idasql accepted it (no error in response).
        """
        try:
            body = self._post(sql)
            # A write typically returns an empty result or {"ok": true}
            # Treat empty body or empty list as success
            text = body.strip()
            if not text or text in ("[]", "{}", "null"):
                return True
            parsed = json.loads(text) if text.startswith(("{", "[")) else None
            if isinstance(parsed, list) and len(parsed) == 0:
                return True
            if isinstance(parsed, dict) and parsed.get("error"):
                raise IdaSQLError(f"idasql error: {parsed['error']}")
            return True
        except IdaSQLError:
            raise
        except Exception:
            return True  # Optimistic: if we got a response, assume it worked

    def health_check(self) -> bool:
        """Return True if idasql is reachable."""
        try:
            req = urllib.request.Request(
                f"{self._url}/status", method="GET"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _post(self, sql: str) -> str:
        data = sql.encode("utf-8")
        req = urllib.request.Request(
            f"{self._url}/query",
            data=data,
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            raise IdaSQLError(f"idasql network error: {e}") from e
        except Exception as e:
            raise IdaSQLError(f"idasql request failed: {e}") from e

    def _parse(self, body: str, sql: str = "") -> list[dict]:
        text = body.strip()
        if not text or text in ("null", "[]", "{}"):
            return []

        # --- Try JSON ---
        if text.startswith("{") or text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                pass
            else:
                # Format (a): array of row objects
                if isinstance(data, list):
                    if len(data) == 0:
                        return []
                    if isinstance(data[0], dict):
                        return data
                    # Array of arrays with no column names — synthesise col_0, col_1, …
                    if isinstance(data[0], list):
                        return [
                            {f"col_{i}": v for i, v in enumerate(row)}
                            for row in data
                        ]
                    # Array of scalars — single-column result
                    return [{"col_0": v} for v in data]

                # Format (b): {"columns": [...], "rows": [[...],...]}
                if isinstance(data, dict):
                    if "error" in data:
                        raise IdaSQLError(f"idasql query error: {data['error']}")
                    if "columns" in data and "rows" in data:
                        cols = data["columns"]
                        return [dict(zip(cols, row)) for row in data["rows"]]
                    # Flat dict — single row
                    return [data]

        # --- Fallback: TSV / plain text ---
        # Treat each non-empty line as {"line": "..."}
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return []

        # If first line looks like a header (no digits, tab-separated)
        if "\t" in lines[0] and len(lines) > 1:
            headers = [h.strip() for h in lines[0].split("\t")]
            rows = []
            for ln in lines[1:]:
                vals = ln.split("\t")
                rows.append(dict(zip(headers, [v.strip() for v in vals])))
            return rows

        return [{"line": ln.strip()} for ln in lines]


# ==========================================================================
# High-level context extraction using SQL
# ==========================================================================

class FunctionContextExtractor:
    """
    Extracts per-function context from an idasql server for LLM analysis.
    All values arrive as SQL query results — no IDA Python required.
    """

    def __init__(self, client: IdaSQLClient, config: dict):
        self._db = client
        self._config = config

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def get_all_auto_functions(self) -> list[dict]:
        """
        Return a list of dicts with keys {address, name, size, end_ea}
        for every function whose name is IDA-auto-generated.
        """
        prefixes = self._config["policy"]["auto_generated_prefixes"]
        conditions = " OR ".join(
            f"name LIKE '{p}%'" for p in prefixes
        )
        sql = (
            f"SELECT address, name, size, end_ea "
            f"FROM funcs WHERE {conditions}"
        )
        return self._db.query(sql)

    def get_function_count(self) -> int:
        """Total functions in the database (all, not just auto-generated)."""
        rows = self._db.query("SELECT COUNT(*) as n FROM funcs")
        if rows:
            v = rows[0].get("n") or rows[0].get("COUNT(*)") or 0
            return int(v)
        return 0

    def extract(self, func_row: dict) -> dict:
        """
        Build a full context dict for a single function row returned by
        get_all_auto_functions().  Never raises — errors produce empty fields.
        """
        ea = int(func_row["address"])
        end_ea = int(func_row.get("end_ea", ea))
        name = str(func_row.get("name", f"sub_{ea:X}"))
        size = int(func_row.get("size", 0))

        max_lines = self._config["analysis"].get("max_pseudocode_lines", 200)

        pseudocode = self._pseudocode(ea, max_lines)
        strings    = self._strings(ea)
        imports    = self._imports(ea)
        callees    = self._callees(ea)
        callers    = self._callers(ea)
        comments   = self._comments(ea)
        bb_count   = self._basic_blocks(ea)

        return {
            "address":           f"0x{ea:X}",
            "address_int":       ea,
            "current_name":      name,
            "prototype":         self._prototype_from_pseudocode(pseudocode),
            "pseudocode":        pseudocode,
            "strings":           strings,
            "imported_apis":     imports,
            "callees":           callees,
            "callers":           callers,
            "comments":          comments,
            "size_bytes":        size,
            "basic_block_count": bb_count,
        }

    # ------------------------------------------------------------------
    # Individual extractors
    # ------------------------------------------------------------------

    def _pseudocode(self, ea: int, max_lines: int) -> str:
        """
        Retrieve Hex-Rays pseudocode for a function.

        Strategy (IDA 9 / idasql SDK 9.0+):
          1. decompile() scalar function  — returns the full body as one string.
          2. pseudocode virtual table     — one row per line, ordered by line_num.
        """
        # --- Primary: decompile() scalar function (idasql / IDA 9) --------
        try:
            rows = self._db.query(f"SELECT decompile({ea}) AS code")
            if rows:
                text_val = rows[0].get("code") or next(iter(rows[0].values()), None)
                if text_val and isinstance(text_val, str) and text_val.strip():
                    return self._trim_lines(text_val, max_lines)
        except IdaSQLError:
            pass

        # --- Fallback: pseudocode virtual table ----------------------------
        # Schema: func_addr (int), line_num (int), line (str)
        try:
            rows = self._db.query(
                f"SELECT line FROM pseudocode "
                f"WHERE func_addr = {ea} "
                f"ORDER BY line_num"
            )
            if not rows:
                return ""

            lines = []
            for row in rows:
                text_val = row.get("line")
                if text_val is None:
                    for col in ("code", "text", "pseudocode", "body", "content"):
                        if col in row:
                            text_val = row[col]
                            break
                    else:
                        text_val = next(
                            (v for v in row.values() if isinstance(v, str)), None
                        )
                if text_val is not None:
                    lines.append(str(text_val))

            return self._trim_lines("\n".join(lines), max_lines)
        except IdaSQLError:
            return ""

    @staticmethod
    def _trim_lines(text: str, max_lines: int) -> str:
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [
                f"// ... [{len(lines) - max_lines} more lines truncated]"
            ]
        return "\n".join(lines)

    def _prototype_from_pseudocode(self, pseudocode: str) -> str:
        """Extract the first non-blank line of pseudocode as the prototype."""
        for line in pseudocode.splitlines():
            s = line.strip()
            if s and not s.startswith("//"):
                return s
        return ""

    def _strings(self, ea: int, limit: int = 12) -> list[str]:
        """Strings referenced by this function via xrefs."""
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT s.content
                FROM strings s
                JOIN xrefs x ON s.address = x.to_ea
                JOIN instructions i ON x.from_ea = i.address
                WHERE i.func_addr = {ea}
                LIMIT {limit}
            """)
            results = []
            for row in rows:
                v = row.get("content") or next(iter(row.values()), None)
                if v and isinstance(v, str) and len(v.strip()) >= 2:
                    results.append(v.strip())
            return results
        except IdaSQLError:
            return []

    def _imports(self, ea: int, limit: int = 15) -> list[str]:
        """Imported API names called by this function."""
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT imp.name, imp.module
                FROM imports imp
                JOIN xrefs x ON imp.address = x.to_ea
                JOIN instructions i ON x.from_ea = i.address
                WHERE i.func_addr = {ea}
                LIMIT {limit}
            """)
            results = []
            for row in rows:
                name   = row.get("name", "")
                module = row.get("module", "")
                if name:
                    results.append(f"{module}!{name}" if module else name)
            return results
        except IdaSQLError:
            return []

    def _callees(self, ea: int, limit: int = 15) -> list[str]:
        """Internal (non-import) functions called by this function."""
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT f2.name
                FROM funcs f2
                JOIN xrefs x ON f2.address = x.to_ea
                JOIN instructions i ON x.from_ea = i.address
                WHERE i.func_addr = {ea}
                  AND x.is_code = 1
                  AND f2.address != {ea}
                LIMIT {limit}
            """)
            return [
                row.get("name") or next(iter(row.values()), "")
                for row in rows
                if row
            ]
        except IdaSQLError:
            return []

    def _callers(self, ea: int, limit: int = 8) -> list[str]:
        """Functions that call this function."""
        # Primary: join via instructions.func_addr (indexed, no range scan needed)
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT f2.name
                FROM xrefs x
                JOIN instructions i ON x.from_ea = i.address
                JOIN funcs f2 ON i.func_addr = f2.address
                WHERE x.to_ea = {ea}
                  AND x.is_code = 1
                  AND f2.address != {ea}
                LIMIT {limit}
            """)
            return [
                row.get("name") or next(iter(row.values()), "")
                for row in rows
                if row
            ]
        except IdaSQLError:
            # Fallback: range join (may be slower but avoids the instructions table)
            try:
                rows = self._db.query(f"""
                    SELECT DISTINCT f2.name
                    FROM funcs f2
                    JOIN xrefs x ON x.from_ea >= f2.address AND x.from_ea < f2.end_ea
                    WHERE x.to_ea = {ea}
                      AND x.is_code = 1
                    LIMIT {limit}
                """)
                return [
                    row.get("name") or next(iter(row.values()), "")
                    for row in rows
                    if row
                ]
            except IdaSQLError:
                return []

    def _comments(self, ea: int) -> list[str]:
        """All comments attached to this function's entry address."""
        try:
            rows = self._db.query(
                f"SELECT * FROM comments WHERE address = {ea}"
            )
            comments = []
            for row in rows:
                for col, val in row.items():
                    if col == "address":
                        continue
                    if isinstance(val, str) and val.strip():
                        comments.append(f"[{col}] {val.strip()}")
            return comments
        except IdaSQLError:
            return []

    def _basic_blocks(self, ea: int) -> int:
        """Number of basic blocks in the function."""
        try:
            rows = self._db.query(
                f"SELECT COUNT(*) as n FROM blocks WHERE func_ea = {ea}"
            )
            if rows:
                v = rows[0].get("n") or rows[0].get("COUNT(*)") or 0
                return int(v)
        except IdaSQLError:
            pass
        return 0

    # ------------------------------------------------------------------
    # Name conflict check (used by renamer)
    # ------------------------------------------------------------------

    def name_exists(self, name: str) -> bool:
        """Return True if name is already used in the database."""
        try:
            rows = self._db.query(
                f"SELECT address FROM funcs WHERE name = '{_sql_escape(name)}' LIMIT 1"
            )
            if rows:
                return True
            # Also check names table
            rows2 = self._db.query(
                f"SELECT address FROM names WHERE name = '{_sql_escape(name)}' LIMIT 1"
            )
            return bool(rows2)
        except IdaSQLError:
            return False


def _sql_escape(s: str) -> str:
    """Minimal SQL string escaping — single quotes only."""
    return s.replace("'", "''")
