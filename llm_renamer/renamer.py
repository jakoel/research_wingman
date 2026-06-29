"""
Safe rename policy for llm_renamer (idapro backend).

RenamePolicy is the only place that calls idc.set_name() to write renames
into the open IDA database.
"""

from .idapro_client import FunctionContextExtractor
from .validator import is_auto_generated_name


class RenamePolicy:
    def __init__(self, config: dict, extractor: FunctionContextExtractor):
        self._config = config
        self._extractor = extractor
        self._max_suffix = int(config["policy"].get("conflict_suffix_max", 9))

    # ------------------------------------------------------------------
    # Policy gate
    # ------------------------------------------------------------------

    def can_rename(self, current_name: str) -> tuple[bool, str]:
        if not is_auto_generated_name(current_name, self._config):
            if self._config["policy"].get("never_overwrite_analyst_names", True):
                return False, (
                    f"Name {current_name!r} is not auto-generated; "
                    "analyst names are protected"
                )
        return True, ""

    # ------------------------------------------------------------------
    # Conflict resolution
    # ------------------------------------------------------------------

    def resolve_conflict(self, name: str) -> str:
        if not self._extractor.name_exists(name):
            return name
        for i in range(2, self._max_suffix + 2):
            candidate = f"{name}_{i}"
            if not self._extractor.name_exists(candidate):
                return candidate
        return ""

    # ------------------------------------------------------------------
    # Rename application
    # ------------------------------------------------------------------

    def apply_rename(self, ea: int, new_name: str, summary: str = "") -> tuple[bool, str]:
        import idc
        ok = idc.set_name(ea, new_name, idc.SN_NOCHECK)
        if not ok:
            return False, f"idc.set_name failed for 0x{ea:X}"
        if summary:
            idc.set_func_cmt(ea, summary, 1)  # repeatable comment, visible in callers too
        return True, new_name
