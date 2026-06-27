"""
Safe rename policy for llm_renamer (idasql backend).

RenamePolicy enforces all protection rules and is the ONLY place that
issues UPDATE funcs SET name = ... to idasql.
"""

from .idasql_client import IdaSQLClient, FunctionContextExtractor, _sql_escape
from .validator import is_auto_generated_name


class RenamePolicy:
    def __init__(self, config: dict, db: IdaSQLClient, extractor: FunctionContextExtractor):
        self._config = config
        self._db = db
        self._extractor = extractor
        self._max_suffix = int(config["policy"].get("conflict_suffix_max", 9))

    # ------------------------------------------------------------------
    # Policy gate
    # ------------------------------------------------------------------

    def can_rename(self, current_name: str) -> tuple[bool, str]:
        """
        Return (allowed, reason).
        Must pass before any rename is attempted.
        """
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
        """
        Return a unique variant of name.  If name is already taken, tries
        name_2, name_3, … up to conflict_suffix_max.
        Returns "" if no unique name can be found.
        """
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

    def apply_rename(self, ea: int, new_name: str) -> tuple[bool, str]:
        """
        Issue UPDATE funcs SET name = new_name WHERE address = ea.
        Returns (success, detail).  detail is new_name on success or
        an error message on failure.
        """
        sql = (
            f"UPDATE funcs SET name = '{_sql_escape(new_name)}' "
            f"WHERE address = {ea}"
        )
        try:
            ok = self._db.execute(sql)
            if ok:
                return True, new_name
            return False, "idasql execute returned False"
        except Exception as e:
            return False, f"rename failed: {e}"
