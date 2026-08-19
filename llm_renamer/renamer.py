"""
Safe rename policy for llm_renamer (idapro backend).

RenamePolicy is the only place that calls idc.set_name() to write renames
into the open IDA database.
"""

from .idapro_client import FunctionContextExtractor
from .validator import is_auto_generated_name


def format_comment(summary: str, confidence: float | None) -> str:
    """Build the repeatable function comment written at apply time: the
    summary plus a trailing confidence annotation, so the score is visible
    in IDA (disassembly view, callers) without opening the KB."""
    if confidence is None:
        return summary
    return f"{summary} (confidence score: {confidence:.2f})"


class RenamePolicy:
    def __init__(self, config: dict, extractor: FunctionContextExtractor):
        self._config = config
        self._extractor = extractor
        self._max_suffix = int(config["policy"].get("conflict_suffix_max", 9))

    # ------------------------------------------------------------------
    # Policy gate
    # ------------------------------------------------------------------

    def can_rename(self, current_name: str, applied_name: str | None = None) -> tuple[bool, str]:
        """
        Decide whether a rename may overwrite the name currently in the database.

        Overwritable = *provisional* names only: IDA auto-generated names
        (`sub_`, `loc_`, ...), this tool's own uncertain `maybe_` hedge, and
        IDA's `unknown_libname_` stub. These were never authored by a human or
        recovered from a real symbol, so overwriting them with a better analysis
        is always fine -- and this is what lets the confidence-override upgrade
        path actually reach the database (e.g. `maybe_check_2` -> `memset_optimized`
        on re-analysis). Previously `maybe_`/`unknown_libname_` fell through to
        the analyst-name guard and got frozen forever.

        `applied_name` is what *this tool* last wrote here. If the live name
        still equals it, the tool owns this name and may reconsider it even if
        it's a real (non-provisional) name -- that's a genuine confidence upgrade
        of our own prior result, not clobbering someone else's work.

        Anything else is a real recovered name -- an IDA library/signature match
        (`memcpy`), an imported or symbol-derived name (`ClfsScanLogContainers`),
        a WPP trace name (`WPP_SF_sqd`), or a human analyst's rename. Those are
        ground truth more reliable than an LLM guess, so they are left untouched.
        (The tool is expected to run before manual analysis, so in practice this
        guard protects IDA's own recovered names, not analyst edits.)
        """
        if self._is_provisional(current_name):
            return True, ""
        if applied_name and current_name == applied_name:
            return True, ""
        return False, (
            f"Name {current_name!r} is a real recovered name "
            "(IDA library/symbol/import or analyst) — not overwriting ground truth"
        )

    def _is_provisional(self, name: str) -> bool:
        """A placeholder/uncertain name safe to overwrite: IDA auto-generated,
        our own `maybe_` hedge, or IDA's `unknown_libname_` stub."""
        if is_auto_generated_name(name, self._config):
            return True
        uncertain = str(self._config["analysis"].get("uncertain_prefix", "maybe_"))
        if uncertain and name.startswith(uncertain):
            return True
        return name.startswith("unknown_libname")

    # ------------------------------------------------------------------
    # Conflict resolution
    # ------------------------------------------------------------------

    def resolve_conflict(self, name: str, ea: int | None = None) -> str:
        if not self._extractor.name_exists(name):
            return name
        for i in range(2, self._max_suffix + 2):
            candidate = f"{name}_{i}"
            if not self._extractor.name_exists(candidate):
                return candidate
        # Numeric suffixes exhausted (a large duplicate-body family, e.g. a
        # dozen structurally-identical thunks all proposing the same generic
        # "wrapper_x" name) -- fall back to the address, which is always
        # unique, instead of giving up and leaving the function unrenamed.
        # Trusted unconditionally (no name_exists check): ea is unique to
        # THIS function by construction, so the only way this candidate
        # could already exist is a different entity coincidentally holding
        # that exact literal string -- astronomically unlikely, and the
        # previous name_exists() check here meant that coincidence, however
        # unlikely, still fell through to the "give up" `return ""` this
        # fallback exists specifically to avoid.
        if ea is not None:
            return f"{name}_{ea:x}"
        return ""

    # ------------------------------------------------------------------
    # Rename application
    # ------------------------------------------------------------------

    def apply_rename(
        self, ea: int, new_name: str, summary: str = "",
        confidence: float | None = None,
    ) -> tuple[bool, str]:
        import idc
        ok = idc.set_name(ea, new_name, idc.SN_NOCHECK)
        if not ok:
            return False, f"idc.set_name failed for 0x{ea:X}"
        if summary:
            # repeatable comment, visible in callers too
            idc.set_func_cmt(ea, format_comment(summary, confidence), 1)
        return True, new_name
