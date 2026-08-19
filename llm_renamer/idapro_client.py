"""
IDA Pro direct client for llm_renamer.

Uses idapro.open_database() to load an IDB and accesses it via the
IDA Python API (idautils, idc, ida_funcs, ida_hexrays, etc.).

All IDA modules are imported lazily inside methods so this module can be
imported before idapro.open_database() is called.
"""

from __future__ import annotations

import re

from .kb import addr_to_hex


# Matches the repeatable comment renamer.format_comment() writes at apply
# time ("<summary> (confidence score: N.NN)") -- a real, live-observed bug:
# on a re-analysis of an already-applied function, that comment is a genuine
# Hex-Rays comment by the time this function decompiles again, so it lands in
# `str(cfunc)` looking exactly like a human analyst's note. Left in, the
# model reads its own prior verdict back as pre-existing documentation and
# can anchor on/repeat a wrong answer instead of re-deriving one. The
# "(confidence score: N.NN)" suffix is unique enough to detect reliably
# without touching a real analyst's own comments. Keep in sync with
# renamer.format_comment() if that format ever changes -- idapro_client.py
# can't import renamer.py (renamer.py imports FunctionContextExtractor from
# here), so the pattern is duplicated, not shared.
_SELF_COMMENT_RE = re.compile(
    r"^[ \t]*//.*\(confidence score: \d+\.\d{2}\)[ \t]*\r?\n?", re.MULTILINE
)


def _strip_self_comment(text: str) -> str:
    return _SELF_COMMENT_RE.sub("", text)


# Same protection as _SELF_COMMENT_RE, for the separate code path that reads
# the comment directly via idc.get_cmt() (_comments(), below) rather than
# seeing it embedded in decompiled pseudocode text -- no leading `//` there
# (that's Hex-Rays' own rendering, not part of the stored comment string),
# so _SELF_COMMENT_RE's anchored pattern doesn't match it; confirmed this
# was a real gap 2026-08-16, the self-comment protection didn't cover this
# path at all. Matches format_comment()'s exact output ("<summary>
# (confidence score: N.NN)") and excludes the WHOLE comment (not just the
# trailing score suffix) -- the risk is the model reading its own full
# prior verdict as if it were pre-existing analyst documentation, same as
# the pseudocode case, not just the numeric annotation on it.
_SELF_COMMENT_SUFFIX_RE = re.compile(r"\(confidence score: \d+\.\d{2}\)\s*$")


def _is_self_comment(text: str) -> bool:
    return bool(_SELF_COMMENT_SUFFIX_RE.search(text.strip()))


# Matches the operator token itself in a demangled `operator()` overload
# name, e.g. "MyClass::operator()" -- see _display_name's use.
_OPERATOR_CALL_RE = re.compile(r"operator\(\)")


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
        """Return dicts with {address, name, size, end_ea} for functions that are
        analysis candidates -- still-unnamed `sub_` functions only (named and
        trivial-stub functions are not worth an LLM call)."""
        import idautils, idc, ida_funcs
        prefixes = self._config["policy"].get("analysis_candidate_prefixes", ["sub_"])
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

    def pseudocode(self, ea: int, max_lines: int | None = None) -> str:
        """Public entry point for callers that need just the decompiled body
        (e.g. `diff`), without building the rest of extract()'s context dict.
        Defaults to the configured analysis cap; pass an explicit max_lines to
        override it (`diff` uses a much higher one -- truncating either side
        of an old-vs-patched comparison silently hides the real difference)."""
        if max_lines is None:
            max_lines = self._config["analysis"].get("max_pseudocode_lines", 200)
        return self._pseudocode(ea, max_lines)

    def extract(self, func_row: dict) -> dict:
        """Build the full context dict for one function row.

        Note: byte size, basic-block count and the bare address are no longer
        extracted for the prompt — they carried no naming signal and
        basic-block count meant a wasted `FlowChart` call per function. The
        graph still records those (via CallGraphBuilder) for scoring/map views.
        """
        ea   = int(func_row["address"])
        name = self.current_name(ea)   # authority, not the possibly-stale row name
        max_lines = self._config["analysis"].get("max_pseudocode_lines", 200)

        pseudocode = self._pseudocode(ea, max_lines)
        # `_trim_lines` embeds a "// ... [N more lines truncated]" marker in
        # the text itself when a real body exceeds max_pseudocode_lines --
        # that's visible to the MODEL, but nothing previously surfaced it to
        # the operator (no console warning, nothing queryable afterward).
        # Confirmed real risk this same session: a too-tight cap silently
        # hides real signal. Detected cheaply by checking for that same
        # marker rather than re-counting lines.
        pseudocode_truncated = "more lines truncated]" in pseudocode
        callee_addr_names = self._callee_addr_names(ea)
        caller_addr_names = self._caller_addr_names(ea)
        indirectly_referenced, indirect_code_referrers = self._indirect_refs(ea)
        return {
            "address":           addr_to_hex(ea),
            "current_name":      name,
            "prototype":         self._prototype_from_pseudocode(pseudocode),
            "type_signature":    self._type_signature(ea),
            "pseudocode":        pseudocode,
            "pseudocode_truncated": pseudocode_truncated,
            "strings":           self._strings(ea),
            "imported_apis":     self._imports(ea),
            "callees":           list(callee_addr_names.values()),
            "callee_addr_names": callee_addr_names,
            "callers":           list(caller_addr_names.values()),
            "caller_addr_names": caller_addr_names,
            "indirectly_referenced":     indirectly_referenced,
            "indirect_code_referrers":   indirect_code_referrers,
            "comments":          self._comments(ea),
        }

    def name_exists(self, name: str) -> bool:
        import idc
        return idc.get_name_ea_simple(name) != idc.BADADDR

    # Argument tokens never worth using as a relevance anchor: they either
    # match too broadly (`this` appears on nearly every line of a method,
    # which would pull in the whole function body) or are C type keywords
    # a decompiled cast can leave inside an argument list.
    _SNIPPET_STOP_TOKENS = frozenset({
        "this", "int", "unsigned", "char", "void", "short", "long", "float",
        "double", "bool", "signed", "const", "struct", "size_t",
    })

    # Hex-Rays' own stack/register bookkeeping comments (`// [esp+D0h]
    # [ebp-14h] BYREF`, `// eax`, `// rcx`) -- IDA-internal annotation, never
    # semantic content, unlike a real written comment. Stripped from snippet
    # output. Covers both 32-bit (esp/ebp/eax..) and 64-bit (rsp/rbp/rax..,
    # r8-r15) forms -- this codebase's real targets are x64 binaries, where
    # 32-bit-only coverage silently let this bookkeeping noise leak straight
    # into the LLM-facing snippet unstripped (confirmed real gap 2026-08-16).
    _STACK_COMMENT = re.compile(
        r"\s*//\s*("
        r"(?:\[(?:esp|ebp|rsp|rbp)[^\]]*\]\s*)+(?:BYREF)?"
        r"|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|[abcd][lh]"
        r"|r(?:8|9|1[0-5])[dwb]?"
        r")\s*$"
    )

    def call_site_snippet(self, ea: int, target_name: str, max_lines: int = 20) -> str:
        """Lines of `ea`'s pseudocode relevant to a call to `target_name` (a
        callee's current live name) -- the call line(s) plus any OTHER line
        that shares an operand with them, not just nearby lines.

        The matching line alone is routinely just `if (target_name(v8, v7))`
        -- the real evidence for what `v7`/`v8` actually ARE (e.g. an EOF
        sentinel vs. a string width) sits a few lines above, where they were
        assigned. A fixed N-line window around the match was tried first and
        pulled in whatever happened to sit nearby regardless of relevance --
        confirmed to twice mislead the refiner into borrowing an unrelated
        neighboring statement's identity or value: an unrelated sibling call
        (`identity_callback(v2)` bled into evidence for a call keyed on `v3`,
        producing a real name collision applied 2026-08-01) and an unrelated
        local's assignment (`v17 = -1` bled into evidence for a call using
        only `v12`, producing a fabricated "-1 default" claim). Tracing
        actual shared operands instead of line distance keeps evidence
        scoped to what the call site's own variables are doing, wherever
        those lines happen to sit, and excludes anything that doesn't touch
        them, however close it sits. Empty string if the name doesn't appear
        or there's no pseudocode."""
        if not target_name:
            return ""
        max_pseudocode_lines = self._config["analysis"].get("max_pseudocode_lines", 200)
        code = self._pseudocode(ea, max_pseudocode_lines)
        if not code:
            return ""
        call_pat = re.compile(r"\b" + re.escape(target_name) + r"\b")
        all_lines = code.splitlines()
        match_idxs = [i for i, ln in enumerate(all_lines) if call_pat.search(ln)]
        if not match_idxs:
            return ""

        # \b prefix matters: without it, this can match a DIFFERENT call
        # whose name merely ends with target_name as a substring (e.g.
        # target_name="Read" matching inside "FastRead(x)" on a line that
        # also has a real, standalone "Read(y)" call) -- pulling the wrong
        # call's arguments into `relevant`, exactly the "unrelated sibling
        # bled into evidence" failure mode this function's docstring above
        # says was already observed twice in production. Confirmed real gap
        # 2026-08-16: call_pat (used to find match lines) already had this
        # boundary, arg_pat (used to extract operands from those lines) did
        # not.
        arg_pat = re.compile(r"\b" + re.escape(target_name) + r"\s*\(([^()]*)\)")
        relevant: set[str] = set()
        for i in match_idxs:
            m = arg_pat.search(all_lines[i])
            if not m:
                continue
            relevant |= {
                tok for tok in re.findall(r"[A-Za-z_]\w*", m.group(1))
                if tok not in self._SNIPPET_STOP_TOKENS
            }

        keep: set[int] = set(match_idxs)
        if relevant:
            var_pat = re.compile(r"\b(?:" + "|".join(re.escape(v) for v in relevant) + r")\b")
            for i, ln in enumerate(all_lines):
                if var_pat.search(ln):
                    keep.add(i)

        # The function's own prototype line (`ret_type name(args) {` split
        # across two lines by Hex-Rays) matches on parameter names alone but
        # carries no evidence -- just re-declares the operands, doesn't show
        # what they hold. Drop it if it snuck in via relevance matching.
        for i in list(keep):
            if i not in match_idxs and i + 1 < len(all_lines) \
                    and all_lines[i + 1].strip() == "{" \
                    and re.search(r"\w+\s*\([^;{}]*\)\s*$", all_lines[i].strip()):
                keep.discard(i)

        # match_idxs (the actual call-site lines -- the entire point of this
        # function) must never be cut by the max_lines budget; only the
        # supporting "shares an operand" lines are trimmed against it.
        # Confirmed real gap 2026-08-16: a plain `sorted(keep)[:max_lines]`
        # truncates by position, so a call site late in a large function
        # with many earlier "relevant" lines could lose every visible call
        # to target_name -- defeating the function's stated purpose.
        match_set = set(match_idxs)  # the prototype-drop loop above never removes these
        support = sorted(keep - match_set)
        budget_left = max(0, max_lines - len(match_set))
        ordered = sorted(match_set | set(support[:budget_left]))
        out: list[str] = []
        prev: int | None = None
        for i in ordered:
            if prev is not None and i != prev + 1:
                out.append("...")
            # Strip Hex-Rays' own stack/register bookkeeping comments (e.g.
            # `// [esp+D0h] [ebp-14h] BYREF`, `// eax`) -- IDA-internal
            # noise, never semantic evidence, unlike a real written comment.
            out.append(self._STACK_COMMENT.sub("", all_lines[i].strip()).rstrip())
            prev = i
        return "\n".join(out)

    def current_name(self, ea: int) -> str:
        """The authoritative current name of a function: whatever the open IDA
        database says right now (an analyst rename, our applied rename, or the
        original auto name). This is the single source of truth for "what is
        this function called" while IDA is open -- never a KB shadow field
        (`old_name`/`applied_name`) nor a cached graph name, both of which are
        historical snapshots that drift. See ARCHITECTURE §3a."""
        import idc
        return idc.get_func_name(ea) or f"sub_{ea:X}"

    def _display_name(self, ea: int) -> str:
        """The name to SHOW a neighbour under in the prompt -- the same form the
        Hex-Rays body uses, not the raw stored symbol.

        On symbol-bearing binaries (PDB/exports) `current_name` returns the raw
        mangled MSVC symbol (`?Initialize@CClfsManagedLogClientUser@@EEAA...`),
        but the decompiled body calls it by its demangled `Class::Method` form
        (`CClfsManagedLogClientUser::Initialize`). Listing a callee/caller under
        the mangled name therefore does two harmful things at once: it injects
        long encoded noise the model has to decode, and it strands the summary
        -- the model can't tie a summary filed under the mangled name to the
        demangled call it sees in the code (the same failure class the sub_ ->
        new_name body rewrite fixes, but for symbol names). Demangle to the
        body's short form (drop the trailing parameter list, which the body
        omits at the call site) so listing and body agree.

        Only affects mangled names: `get_short_name` returns the plain name
        unchanged for `sub_`/analyst/clean names, so those pass straight
        through. `current_name` (the rename authority) is deliberately left
        raw -- this is a display-only transform."""
        import idc, ida_name
        raw = idc.get_func_name(ea) or f"sub_{ea:X}"
        try:
            short = ida_name.get_short_name(ea)
        except Exception:
            short = ""
        if short and short != raw:
            # An `operator()` overload's own name contains a `(` before the
            # real parameter list starts (e.g. "MyClass::operator()(int)
            # const") -- a plain split-at-first-"(" cuts the name itself in
            # half, producing malformed "MyClass::operator" instead of
            # "MyClass::operator()". `operator[]` doesn't have this problem
            # (no `(` in the operator token itself), so only this one case
            # needs special handling.
            m = _OPERATOR_CALL_RE.search(short)
            base = short[:m.end()] if m else short.split("(", 1)[0].strip()
            if base:
                return base
        return raw

    # ── per-function extractors ─────────────────────────────────────────────

    def _type_signature(self, ea: int) -> str:
        """IDA's own C type for the function, when it has one. Often empty or
        equal to the decompiler's inferred prototype for plain sub_ functions,
        but richer for library-recognised/typed functions -- prompts.py shows
        it only when it differs from the pseudocode prototype."""
        import idc
        try:
            return (idc.get_type(ea) or "").strip()
        except Exception:
            return ""

    def _pseudocode(self, ea: int, max_lines: int) -> str:
        # Narrowly scoped to the IDA/Hex-Rays side only (module import, the
        # decompile itself, and rendering cfunc_t to text -- all of which can
        # legitimately fail per-function) so a real bug in `_trim_lines` (pure
        # Python, no IDA dependency) raises visibly instead of being silently
        # swallowed as "this function has no pseudocode" -- the same failure
        # shape already found and fixed in `sink_argument_taint` below.
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            text = str(cfunc) if cfunc else ""
        except Exception:
            return ""
        return self._trim_lines(_strip_self_comment(text), max_lines)

    def sink_argument_taint(self, ea: int, sink_names: set[str]) -> list[dict]:
        """Real dataflow, not graph-topology guessing: for a function already
        known (via the call graph's `dangerous_sink_calls`) to call a
        dangerous sink, determine whether any of THAT SPECIFIC CALL's
        arguments trace back to the function's OWN input parameters --
        `input_reachable` only ever meant "some path exists from an entry
        point to this function," with zero awareness of which argument or
        whether the dangerous operation even touches attacker-influenced
        data at all.

        Walks Hex-Rays' ctree (not text/regex on pseudocode, which variable
        renaming or nested parens can fool) for each call to a name in
        `sink_names`: resolves the callee via the same `_import_map()` the
        call graph itself uses (consistency with how `dangerous_sink_calls`
        was determined), then recursively checks each argument expression
        for a `cot_var` node referencing an `lvar_t` where `is_arg_var()` is
        true -- directly (`memcpy(dst, a2, len)`) or through simple
        arithmetic/derefs/casts (`memcpy(dst, a2 + 16, len)`).

        Deliberately a SEPARATE decompile from `_pseudocode` (bounded cost:
        only called for the small subset of functions the graph already
        flagged as calling a sink, not every function -- Hex-Rays also
        caches per-ea within a session, so this is normally a fast cache hit,
        not a full re-decompile) rather than restructuring `_pseudocode` to
        return the raw `cfunc_t`, keeping this addition isolated with zero
        risk to the existing extraction path.

        Returns e.g. [{"sink": "memcpy", "tainted_args": [2]}] -- 1-indexed
        argument positions, human-readable. Empty list (never raises) if
        decompilation fails or nothing matches."""
        try:
            import ida_hexrays
        except Exception:
            return []
        try:
            cfunc = ida_hexrays.decompile(ea)
        except Exception:
            cfunc = None
        if not cfunc:
            return []

        import_map = self._import_map()

        def resolve_callee_name(target_expr) -> str:
            if target_expr is None:
                return ""
            if target_expr.op == ida_hexrays.cot_obj:
                ea2 = target_expr.obj_ea
                if ea2 in import_map:
                    return import_map[ea2][1]
                import idc
                return idc.get_func_name(ea2) or ""
            if target_expr.op == ida_hexrays.cot_helper:
                return target_expr.helper or ""
            return ""

        def references_arg_var(expr) -> bool:
            if expr is None:
                return False
            if expr.op == ida_hexrays.cot_var:
                lvar = cfunc.lvars[expr.v.idx]
                return lvar.is_arg_var
            found = False
            for sub in (expr.x, expr.y, expr.z):
                if sub is not None and references_arg_var(sub):
                    found = True
            if expr.op == ida_hexrays.cot_call and expr.a:
                for arg in expr.a:
                    if references_arg_var(arg):
                        found = True
            return found

        findings: list[dict] = []

        class _SinkCallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

            def visit_expr(self, expr):
                if expr.op == ida_hexrays.cot_call:
                    name = resolve_callee_name(expr.x)
                    if name in sink_names and expr.a:
                        tainted = [i + 1 for i, arg in enumerate(expr.a)
                                   if references_arg_var(arg)]
                        if tainted:
                            findings.append({"sink": name, "tainted_args": tainted})
                return 0

        _SinkCallVisitor().apply_to(cfunc.body, None)
        return findings

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

    def _strings(self, ea: int) -> list[str]:
        """Every string literal referenced by this function -- NOT truncated
        here. A C++ qualified method name (contains `::`) is the single
        strongest naming signal available (a WPP trace string is very likely
        the function's own name, see prompts.method_name_strings); an
        extraction-level cap risked silently dropping one whenever it sat
        past the scan/display cutoff in address order (previously mitigated
        by scanning ahead of the display limit, but that only pushed the
        blind spot further out, not removed it). How many of the generic
        (non-method-name) remainder get SHOWN is a presentation decision,
        made downstream by prompts.py's `analysis.max_referenced_strings_shown`
        (config-driven) -- `method_name_strings` there elevates every real
        method-name string unconditionally, so none of them ever compete
        with the generic cap regardless of how large this list is."""
        import idautils
        string_map = self._string_map()
        collected: list[str] = []
        seen: set[int] = set()
        for item in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item, 0):
                if xref.to in string_map and xref.to not in seen:
                    seen.add(xref.to)
                    collected.append(string_map[xref.to])
        method_like = [s for s in collected if "::" in s]
        others = [s for s in collected if "::" not in s]
        return method_like + others

    def _imports(self, ea: int) -> list[str]:
        """Every distinct imported API this function calls -- NOT truncated
        here (a bare `limit=15` default silently dropped anything past
        position 15 in address order, e.g. a real memcpy sink at position 18,
        confirmed live 2026-08-16). How many get SHOWN in a prompt is a
        presentation decision, made downstream by prompts.py's
        `analysis.max_imported_apis_shown` (config-driven); this method's job
        is to report the truth, not pre-decide what's worth seeing."""
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
        return results

    def _callee_addr_names(self, ea: int) -> dict[str, str]:
        """Ordered {hex-address: live-name} for this function's direct internal
        callees (imports excluded). Names resolved via current_name() so callers
        get the authoritative current name keyed by address -- what lets prompt
        building substitute a callee's real name into the body by matching the
        live token, rather than guessing from a KB shadow (see prompts.py).

        NOT truncated here -- unlike a display cap, this map must cover EVERY
        real callee, or `substitute_callee_names` silently fails to rewrite
        the raw `sub_XXXXX` tokens for whichever callees fell past the old
        `limit=15` default, stranding their neighbour summaries even though
        the summary section itself is uncapped (§7.1e). Confirmed live
        2026-08-16 on a 64-callee function: 49 of 64 had no entry under the
        old cap."""
        import idautils, ida_funcs
        out: dict[str, str] = {}
        import_map = self._import_map()
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
                    out[addr_to_hex(to)] = self._display_name(to)
        return out

    def _caller_addr_names(self, ea: int) -> dict[str, str]:
        """Ordered {hex-address: live-name} for this function's direct callers.
        Mirrors `_callee_addr_names` -- keyed by address so prompt building can
        resolve a KB row to the name the database actually shows right now,
        rather than a KB shadow field that may be a stale or pre-uniquification
        snapshot (see ARCHITECTURE §3a). Not truncated, same reason as
        `_callee_addr_names`."""
        import idautils, ida_funcs
        out: dict[str, str] = {}
        seen: set[int] = set()
        for xref in idautils.XrefsTo(ea, 0):
            if not xref.iscode:
                continue
            func = ida_funcs.get_func(xref.frm)
            if func and func.start_ea != ea and func.start_ea not in seen:
                seen.add(func.start_ea)
                out[addr_to_hex(func.start_ea)] = self._display_name(func.start_ea)
        return out

    # Exception-unwind sections reference EVERY function's entry as data
    # (RUNTIME_FUNCTION / unwind info), so a data xref from one of these carries
    # no dispatch meaning -- measured: all 941 functions in the CLFS sample have
    # a .pdata data ref. Only a NON-unwind data ref (a .rdata/.data vtable or
    # dispatch table, or an offset embedded in .text code) means the function is
    # actually reachable through a pointer.
    _UNWIND_SEGS = frozenset({".pdata", ".xdata"})

    def _indirect_refs(self, ea: int) -> tuple[bool, list[str]]:
        """Detect indirect reachability the direct (code-xref) call graph misses.

        Returns (indirectly_referenced, code_referrer_names) -- the referrer
        list is NOT truncated here; how many get SHOWN is a presentation
        decision made downstream by prompts.py's
        `analysis.max_code_referrers_shown` (config-driven).

        Virtual methods, registered callbacks and dispatch-table entries are
        invoked through a function pointer, so they have zero *direct* code
        callers -- on the CLFS sample 300 of 323 caller_count==0 functions are
        exactly this, and without a signal the prompt just says "no callers" and
        leaves the model to guess entry-point vs. dead code vs. dispatch target.
        The reliable, deterministic tell is a DATA xref to the entry from a
        non-unwind section (see `_UNWIND_SEGS`): a `.rdata`/`.data` vtable/table
        slot, or an offset baked into `.text` code.

        When that referrer is `.text` code inside another function, that function
        is named (demangled) -- the one indirect relationship resolvable for free
        and concretely, e.g. a constructor that registers this function as an IRP
        cancel-safe-queue callback. `.rdata` vtable slots are not owned by any
        function, so they only set the boolean; deliberately NOT walked back to a
        constructor, which measured unreliable and would fabricate a caller."""
        import ida_xref, ida_segment, ida_funcs
        indirectly_referenced = False
        referrers: list[str] = []
        seen: set[int] = set()
        xr = ida_xref.xrefblk_t()
        ok = xr.first_to(ea, ida_xref.XREF_DATA)
        while ok:
            seg = ida_segment.getseg(xr.frm)
            segname = ida_segment.get_segm_name(seg) if seg else ""
            if segname not in self._UNWIND_SEGS:
                indirectly_referenced = True
                func = ida_funcs.get_func(xr.frm)
                if func and func.start_ea != ea and func.start_ea not in seen:
                    seen.add(func.start_ea)
                    referrers.append(self._display_name(func.start_ea))
            ok = xr.next_to()
        return indirectly_referenced, referrers

    def _comments(self, ea: int) -> list[str]:
        import idc
        comments = []
        for repeatable in (0, 1):
            c = idc.get_cmt(ea, repeatable)
            if c and not _is_self_comment(c):
                label = "repeatable" if repeatable else "regular"
                comments.append(f"[{label}] {c}")
        return comments
