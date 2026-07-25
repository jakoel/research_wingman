#!/usr/bin/env python3
"""
main.py and query.py have been replaced by a single command: rh.py

This shim exists only to point you at the new commands. It does nothing else.
"""

import sys

_MAPPING = [
    ("main.py --database DB",                 "rh.py analyze DB"),
    ("main.py --database DB --quick",         "rh.py analyze DB --quick"),
    ("main.py --database DB --function F",    "rh.py analyze DB -f F"),
    ("main.py --database DB --limit N",       "rh.py analyze DB --limit N"),
    ("main.py --database DB --apply",         "rh.py analyze DB  then  rh.py apply DB"),
    ("main.py --database DB --apply-file F",  "rh.py apply DB"),
    ("main.py --database DB --build-index",   "(automatic — rh.py ask builds it)"),
    ("main.py --database DB --clear-checkpoint", "rh.py analyze DB --reset"),
    ("main.py --database DB --no-resume",     "rh.py analyze DB --reset"),
    ("main.py --database DB --skip-refine",   "rh.py analyze DB --no-refine"),
    ("query.py \"question\"",                 "rh.py ask DB \"question\""),
    ("query.py --report",                     "rh.py ask DB --report"),
    ("query.py --chain ADDR",                 "rh.py ask DB --chain ADDR"),
    ("query.py --score-report",               "rh.py ask DB --scores"),
]


def main() -> None:
    print(__doc__)
    print("  Old command                                  New command")
    print("  " + "─" * 76)
    for old, new in _MAPPING:
        print(f"  {old:<44} {new}")
    print(
        "\n  Two rules worth knowing:\n"
        "    analyze never modifies the database.\n"
        "    apply never calls the LLM.\n"
        "\n  State now lives in <database>.rh/ next to the database,\n"
        "  not in the directory you run from.\n"
        "\n  Start with:  python rh.py status <database>.i64\n"
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
