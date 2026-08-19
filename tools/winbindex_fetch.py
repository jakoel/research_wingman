#!/usr/bin/env python3
"""
winbindex_fetch.py -- pull real Windows system binaries from WinBinDex
(https://winbindex.m417z.com) for patch-diffing, without a browser.

WinBinDex indexes every build of every Windows system file it has seen and
constructs a download link into Microsoft's *public* symbol server
(msdl.microsoft.com) for each one -- no login, no EV license, just the
timestamp + image size baked into the URL. This script automates: find the
file's index -> list its builds for one CPU architecture -> download two
(by default the two most recent *consecutive* builds within the same OS
branch, e.g. two builds of 24H2 back to back) -> verify each download's
SHA-256 against what WinBinDex recorded, so a corrupted/wrong download is
never silently used as input to analysis.

Discovered API shape (undocumented, found 2026-08-07 by testing against the
real site -- there is no official "raw JSON" doc):

  1. Per-filename data lives at, one file per indexed filename, GZIPPED,
     LOWERCASE filename:
       https://raw.githubusercontent.com/m417z/winbindex/gh-pages/data/by_filename_compressed/<filename lowercase>.json.gz
     e.g. clfs.sys -> .../by_filename_compressed/clfs.sys.json.gz
     Gotcha: GitHub's Contents API directory listing for that folder
     TRUNCATES at 1000 entries (it holds tens of thousands) -- don't list
     the directory, query the specific file path directly:
       GET https://api.github.com/repos/m417z/winbindex/contents/data/by_filename_compressed/<name>.json.gz?ref=gh-pages
     -> response JSON has "download_url" pointing at the raw content above.

  2. That per-file JSON is keyed by sha256, each entry shaped like:
       { "<sha256>": {
           "fileInfo": {
             "size": int, "timestamp": int, "virtualSize": int,
             "machineType": int (34404 = 0x8664 = amd64, 332 = 0x14c = x86,
                                  452 = 0x1c4 = ARM, 43620 = 0xAA64 = ARM64),
             "version": "10.0.26100.8875 (WinBuild.160101.0800)", ...
           },
           # A handful of builds (observed: 1/548 for tcpip.sys) have no
           # `virtualSize` -- only lastSectionVirtualAddress/PointerToRawData
           # instead. list_builds() skips those rather than reconstructing
           # SizeOfImage from raw section fields for what's a rare gap.
           "windowsVersions": {
             "<release, e.g. 11-24H2>": { "<KBnnnnnnn>": {
                 "updateInfo": {"releaseDate": "2026-07-14", ...}
             }, ... }, ...
           }
       }, ... }
     Each key is a DISTINCT build (by content hash); the same build can
     appear under several KBs if it wasn't superseded every month.

  3. Download URL construction (from WinBinDex's own writeup) -- the
     timestamp and (page-aligned) image size are baked into a symbol-server
     path, no separator, timestamp uppercase hex / size lowercase hex:
       https://msdl.microsoft.com/download/symbols/<filename>/<TIMESTAMP:08X><SIZE:x>/<filename>
     `virtualSize` in fileInfo IS the page-aligned SizeOfImage already --
     use it directly, don't recompute from sections.

Usage:
    python winbindex_fetch.py clfs.sys --list                 show amd64 builds, newest first
    python winbindex_fetch.py clfs.sys --branch 26100          filter to one OS branch (build-number prefix)
    python winbindex_fetch.py clfs.sys --branch 26100 --pull-latest-pair --out DIR
                                                                 download the two newest CONSECUTIVE
                                                                 builds in that branch (verified by hash)
    python winbindex_fetch.py clfs.sys --pull VERSION1 VERSION2 --out DIR
                                                                 download two specific versions by their
                                                                 full version string (or a unique prefix)

Only stdlib -- no requests/urllib3 dependency, matches the rest of this repo.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import urllib.request
from urllib.error import HTTPError, URLError

_GITHUB_API = "https://api.github.com/repos/m417z/winbindex/contents/data/by_filename_compressed"
_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

_MACHINE_TYPES = {
    332: "x86",
    34404: "amd64",
    452: "arm",
    43620: "arm64",
}
_ARCH_TO_MACHINE_TYPE = {v: k for k, v in _MACHINE_TYPES.items()}


def _get(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "winbindex_fetch/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def fetch_index(filename: str) -> dict:
    """Download and decompress the per-filename WinBinDex index.

    Queries the specific file path (not a directory listing -- the listing
    truncates at 1000 entries for this directory, see module docstring).
    """
    meta_url = f"{_GITHUB_API}/{filename.lower()}.json.gz?ref=gh-pages"
    try:
        meta = json.loads(_get(meta_url))
    except HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"'{filename}' is not indexed by WinBinDex (404 on {meta_url}).\n"
                              f"Check the exact filename (case-insensitive is fine, this script "
                              f"lowercases it) at https://winbindex.m417z.com/?file={filename}")
        raise
    raw = _get(meta["download_url"])
    return json.loads(gzip.GzipFile(fileobj=io.BytesIO(raw)).read())


def list_builds(index: dict, arch: str, branch: str | None) -> list[dict]:
    """Flatten the index into one row per (sha256, build), sorted by earliest
    KB release date, optionally filtered to one architecture and one OS
    branch (a build-number prefix, e.g. "26100" or "19041")."""
    machine_type = _ARCH_TO_MACHINE_TYPE.get(arch)
    if machine_type is None:
        raise SystemExit(f"unknown --arch {arch!r}; choose one of {sorted(_ARCH_TO_MACHINE_TYPE)}")

    rows = []
    for sha256, entry in index.items():
        fi = entry["fileInfo"]
        if fi.get("machineType") != machine_type:
            continue
        version = fi.get("version", "")
        if branch and f".{branch}." not in version:
            continue
        if "virtualSize" not in fi:
            # Rare WinBinDex data gap -- a handful of builds only have raw section
            # pointers (lastSectionVirtualAddress/PointerToRawData) instead of a
            # precomputed page-aligned image size. Not worth reconstructing SizeOfImage
            # from those for what's normally ~1 build out of several hundred; skip it
            # rather than crash or guess at a download URL that might be wrong.
            print(f"  (skipping {version or sha256[:12]}: WinBinDex has no virtualSize for this build)")
            continue
        dates = [
            kb_info["updateInfo"]["releaseDate"]
            for release in entry.get("windowsVersions", {}).values()
            for kb_info in release.values()
            if kb_info.get("updateInfo", {}).get("releaseDate")
        ]
        rows.append({
            "sha256": sha256,
            "version": version,
            "timestamp": fi["timestamp"],
            "virtual_size": fi["virtualSize"],
            "size": fi["size"],
            "first_seen": min(dates) if dates else None,
        })
    # A build with no known release date at all is most plausibly a very
    # recently indexed one (not yet tied to a public KB) -- i.e. likely the
    # NEWEST, not the oldest. Sorting `None -> ""` would put it FIRST
    # (lexicographically smallest), the wrong end for `--pull-latest-pair`'s
    # `rows[-2:]` "two most recent" pick. Sort undated builds last instead
    # (assume newest) -- confirmed real gap 2026-08-16.
    rows.sort(key=lambda r: (r["first_seen"] is None, r["first_seen"] or ""))
    return rows


def download_url_for(filename: str, row: dict) -> str:
    ts_hex = f"{row['timestamp']:08X}"
    size_hex = f"{row['virtual_size']:x}"
    return f"{_SYMBOL_SERVER}/{filename}/{ts_hex}{size_hex}/{filename}"


def download_and_verify(filename: str, row: dict, out_path: str) -> None:
    url = download_url_for(filename, row)
    print(f"  downloading {row['version']}  <-  {url}")
    data = _get(url)
    got_hash = hashlib.sha256(data).hexdigest()
    if got_hash != row["sha256"]:
        raise SystemExit(f"  HASH MISMATCH for {row['version']}: got {got_hash}, "
                          f"WinBinDex says {row['sha256']}. Not writing -- do not trust this file.")
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"  OK -> {out_path}  ({len(data)} bytes, sha256 verified)")


def cmd_list(args) -> None:
    index = fetch_index(args.filename)
    rows = list_builds(index, args.arch, args.branch)
    print(f"{len(rows)} {args.arch} build(s)"
          + (f" in branch {args.branch}" if args.branch else "") + ":\n")
    for r in rows:
        print(f"  {r['first_seen'] or '?':10}  {r['version']:45}  {r['size']:>8} bytes")


def cmd_pull_latest_pair(args) -> None:
    import os
    index = fetch_index(args.filename)
    rows = list_builds(index, args.arch, args.branch)
    if len(rows) < 2:
        raise SystemExit(f"only {len(rows)} matching build(s) found -- need at least 2. "
                          f"Try without --branch, or check --list first.")
    old, patched = rows[-2], rows[-1]
    print(f"Consecutive pair in this branch:\n"
          f"  old     : {old['version']}  ({old['first_seen']})\n"
          f"  patched : {patched['version']}  ({patched['first_seen']})\n")

    os.makedirs(args.out, exist_ok=True)
    old_path = os.path.join(args.out, f"{args.filename}.{_safe(old['version'])}.old")
    patched_path = os.path.join(args.out, f"{args.filename}.{_safe(patched['version'])}.patched")
    download_and_verify(args.filename, old, old_path)
    download_and_verify(args.filename, patched, patched_path)


def cmd_pull(args) -> None:
    import os
    index = fetch_index(args.filename)
    rows = list_builds(index, args.arch, None)
    os.makedirs(args.out, exist_ok=True)
    for version_query in args.pull:
        matches = [r for r in rows if version_query in r["version"]]
        if not matches:
            raise SystemExit(f"no {args.arch} build matching {version_query!r}")
        if len(matches) > 1:
            raise SystemExit(f"{version_query!r} matches {len(matches)} builds -- be more specific:\n"
                              + "\n".join(f"  {m['version']}" for m in matches))
        row = matches[0]
        out_path = os.path.join(args.out, f"{args.filename}.{_safe(row['version'])}")
        download_and_verify(args.filename, row, out_path)


def _safe(version: str) -> str:
    return version.split(" ")[0]  # drop the "(WinBuild...)" suffix, keep just "10.0.26100.8875"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("filename", help="e.g. clfs.sys")
    ap.add_argument("--arch", default="amd64", choices=sorted(_ARCH_TO_MACHINE_TYPE))
    ap.add_argument("--branch", metavar="BUILDPREFIX",
                     help="filter to one OS branch, e.g. 26100 (Win11 24H2), 19041 (20H2/21H1/21H2)")
    ap.add_argument("--out", default=".", help="output directory for --pull / --pull-latest-pair")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list matching builds and exit")
    group.add_argument("--pull-latest-pair", action="store_true",
                        help="download the two newest consecutive builds (needs --branch for a clean pair)")
    group.add_argument("--pull", nargs="+", metavar="VERSION",
                        help="download specific version(s) by full version or unique substring")
    args = ap.parse_args()
    # `filename` reaches os.path.join(args.out, ...) unsanitized further
    # down -- a value containing "../" or path separators could otherwise
    # write outside `args.out`. No-op for a real filename (e.g. "clfs.sys"),
    # which is the only thing this tool's WinBinDex lookup accepts anyway.
    args.filename = os.path.basename(args.filename)

    try:
        if args.list:
            cmd_list(args)
        elif args.pull_latest_pair:
            cmd_pull_latest_pair(args)
        else:
            cmd_pull(args)
    except (HTTPError, URLError) as e:
        raise SystemExit(f"network error: {e}")


if __name__ == "__main__":
    main()
