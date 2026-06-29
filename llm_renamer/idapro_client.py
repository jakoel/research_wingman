"""
IDA Pro direct client for llm_renamer.

Uses idapro.open_database() to load an IDB and accesses it via the
IDA Python API (idautils, idc, ida_funcs, ida_hexrays, etc.).

All IDA modules are imported lazily inside methods so this module can be
imported before idapro.open_database() is called.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Shared cache builders  (called once per session, after open_database)
# ---------------------------------------------------------------------------

def _build_import_cache() -> dict[int, tuple[str, str]]:
    """Return ea -> (module_name, import_name) for every import in the IDB."""
    import ida_nalt
    cache: dict[int, tuple[str, str]] = {}
    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        module = ida_nalt.get_import_module_name(i) or ""
        def _cb(ea, name, ordinal, _mod=module):
            cache[ea] = (_mod, name or f"ord_{ordinal}")
            return True
        ida_nalt.enum_import_names(i, _cb)
    return cache


def _build_string_cache() -> dict[int, str]:
    """Return ea -> decoded string content for all strings defined in the IDB."""
    import idautils
    cache: dict[int, str] = {}
    for s in idautils.Strings():
        try:
            content = str(s)
            if content and len(content.strip()) >= 2:
                cache[s.ea] = content
        except Exception:
            pass
    return cache


# ---------------------------------------------------------------------------
# FunctionContextExtractor
# ---------------------------------------------------------------------------

class FunctionContextExtractor:
    """
    Extracts per-function context from an open IDA database.

    The import map and string map are built lazily on first use and cached
    for the lifetime of this object — both are also shared with
    CallGraphBuilder to avoid rebuilding them during Phase 1.
    """

    def __init__(self, config: dict) -> None:
        self._config = config
        self._import_cache: dict[int, tuple[str, str]] | None = None
        self._string_cache: dict[int, str] | None = None

    # ── cache accessors (package-internal, used by call_graph.py) ──────────

    def _import_map(self) -> dict[int, tuple[str, str]]:
        if self._import_cache is None:
            print("[idapro] Building import cache…")
            self._import_cache = _build_import_cache()
        return self._import_cache

    def _string_map(self) -> dict[int, str]:
        if self._string_cache is None:
            print("[idapro] Building string cache…")
            self._string_cache = _build_string_cache()
        return self._string_cache

    # ── public interface (mirrors the old FunctionContextExtractor) ─────────

    def get_all_auto_functions(self) -> list[dict]:
        """Return dicts with {address, name, size, end_ea} for auto-named functions."""
        import idautils, idc, ida_funcs
        prefixes = self._config["policy"]["auto_generated_prefixes"]
        result = []
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if any(name.startswith(p) for p in prefixes):
                func = ida_funcs.get_func(ea)
                result.append({
                    "address": ea,
                    "name":    name,
                    "size":    (func.end_ea - func.start_ea) if func else 0,
                    "end_ea":  func.end_ea if func else ea,
                })
        return result

    def get_functions_by_name(self, targets: list[str]) -> list[dict]:
        """
        Look up specific functions by name or hex address (e.g. "sub_1c0012232"
        or "0x1c0012232").  Returns dicts with {address, name, size, end_ea}.
        Warns and skips targets that cannot be resolved.
        """
        import idc, ida_funcs
        result = []
        seen: set[int] = set()
        for target in targets:
            ea = None
            if target.startswith(("0x", "0X")):
                try:
                    ea = int(target, 16)
                except ValueError:
                    pass
            if ea is None:
                raw = idc.get_name_ea_simple(target)
                if raw == idc.BADADDR:
                    print(f"[llm_renamer] WARNING: not found in database: {target!r}")
                    continue
                ea = raw
            func = ida_funcs.get_func(ea)
            if not func:
                print(f"[llm_renamer] WARNING: no function at 0x{ea:X} ({target!r})")
                continue
            start = func.start_ea
            if start in seen:
                continue
            seen.add(start)
            result.append({
                "address": start,
                "name":    idc.get_func_name(start) or f"sub_{start:X}",
                "size":    func.end_ea - func.start_ea,
                "end_ea":  func.end_ea,
            })
        return result

    def get_function_count(self) -> int:
        import ida_funcs
        return ida_funcs.get_func_qty()

    def extract(self, func_row: dict) -> dict:
        """Build the full context dict for one function row."""
        ea   = int(func_row["address"])
        name = str(func_row.get("name", f"sub_{ea:X}"))
        size = int(func_row.get("size", 0))
        max_lines = self._config["analysis"].get("max_pseudocode_lines", 200)

        pseudocode = self._pseudocode(ea, max_lines)
        return {
            "address":           f"0x{ea:X}",
            "address_int":       ea,
            "current_name":      name,
            "prototype":         self._prototype_from_pseudocode(pseudocode),
            "pseudocode":        pseudocode,
            "strings":           self._strings(ea),
            "imported_apis":     self._imports(ea),
            "callees":           self._callees(ea),
            "callers":           self._callers(ea),
            "comments":          self._comments(ea),
            "size_bytes":        size,
            "basic_block_count": self._basic_blocks(ea),
        }

    def name_exists(self, name: str) -> bool:
        import idc
        return idc.get_name_ea_simple(name) != idc.BADADDR

    # ── per-function extractors ─────────────────────────────────────────────

    def _pseudocode(self, ea: int, max_lines: int) -> str:
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                return self._trim_lines(str(cfunc), max_lines)
        except Exception:
            pass
        return ""

    @staticmethod
    def _trim_lines(text: str, max_lines: int) -> str:
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [
                f"// ... [{len(lines) - max_lines} more lines truncated]"
            ]
        return "\n".join(lines)

    @staticmethod
    def _prototype_from_pseudocode(pseudocode: str) -> str:
        for line in pseudocode.splitlines():
            s = line.strip()
            if s and not s.startswith("//"):
                return s
        return ""

    def _strings(self, ea: int, limit: int = 12) -> list[str]:
        import idautils
        string_map = self._string_map()
        results: list[str] = []
        seen: set[int] = set()
        for item in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item, 0):
                if xref.to in string_map and xref.to not in seen:
                    seen.add(xref.to)
                    results.append(string_map[xref.to])
                    if len(results) >= limit:
                        return results
        return results

    def _imports(self, ea: int, limit: int = 15) -> list[str]:
        import idautils
        import_map = self._import_map()
        results: list[str] = []
        seen: set[int] = set()
        for item in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item, 0):
                if xref.iscode and xref.to in import_map and xref.to not in seen:
                    seen.add(xref.to)
                    module, name = import_map[xref.to]
                    results.append(f"{module}!{name}" if module else name)
                    if len(results) >= limit:
                        return results
        return results

    def _callees(self, ea: int, limit: int = 15) -> list[str]:
        import idautils, idc, ida_funcs
        import_map = self._import_map()
        results: list[str] = []
        seen: set[int] = set()
        for item in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item, 0):
                if not xref.iscode:
                    continue
                to = xref.to
                if to == ea or to in import_map or to in seen:
                    continue
                func = ida_funcs.get_func(to)
                if func and func.start_ea == to:
                    seen.add(to)
                    results.append(idc.get_func_name(to) or f"sub_{to:X}")
                    if len(results) >= limit:
                        return results
        return results

    def _callers(self, ea: int, limit: int = 8) -> list[str]:
        import idautils, idc, ida_funcs
        results: list[str] = []
        seen: set[int] = set()
        for xref in idautils.XrefsTo(ea, 0):
            if not xref.iscode:
                continue
            func = ida_funcs.get_func(xref.frm)
            if func and func.start_ea != ea and func.start_ea not in seen:
                seen.add(func.start_ea)
                results.append(idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}")
                if len(results) >= limit:
                    return results
        return results

    def _comments(self, ea: int) -> list[str]:
        import idc
        comments = []
        for repeatable in (0, 1):
            c = idc.get_cmt(ea, repeatable)
            if c:
                label = "repeatable" if repeatable else "regular"
                comments.append(f"[{label}] {c}")
        return comments

    def _basic_blocks(self, ea: int) -> int:
        import ida_funcs, ida_gdl
        func = ida_funcs.get_func(ea)
        if not func:
            return 0
        try:
            return sum(1 for _ in ida_gdl.FlowChart(func))
        except Exception:
            return 0
