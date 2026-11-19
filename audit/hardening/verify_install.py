#!/usr/bin/env python3
"""Pre-deployment verification of an installed dbos==3.6.0 MIT-only environment.

Run it WITH THE INTERPRETER OF THE ENVIRONMENT TO BE DEPLOYED, in isolated mode:

    /path/to/venv/bin/python -I verify_install.py [--lock requirements-min.lock.txt]
                                                  [--wheel dbos-3.6.0-py3-none-any.whl]
                                                  [--allow-pth NAME.pth] [--allow-file PATH] [--json]

Checks (any failure => exit status 1):
  1. dbos distribution is exactly 3.6.0.
  2. Every file of the dbos wheel is present and matches the sha256 in its RECORD; the set of
     (path, sha256) pairs equals the manifest of the genuine PyPI wheel
     (wheel sha256 bed76236...58ac), pinned below as a digest; no unrecorded files in dbos/.
  3. (--wheel) the wheel file itself has the known-good sha256.
  4. Absent: dbos-enterprise / dbos_enterprise, psycopg-binary, psycopg-c, psycopg2*,
     any opentelemetry distribution or module, websockets (only the Conductor client needs it).
  5. No .pth files and no sitecustomize/usercustomize in any site directory (start-up code hooks).
  6. psycopg runs in pure-Python mode on the system libpq; prints the libpq version.
  7. dbos contains exactly one unpickling call site (dbos/_serialization.py) -- the assumption
     dbos_hardening.install_pickle_guard relies on.
  8. (--lock) every installed distribution is pinned in the lock at the installed version.
Always prints the resolved dependency versions.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata as md
import importlib.util
import json
import os
import re
import site
import sys
from typing import Dict, List, Tuple

EXPECTED_VERSION = "3.6.0"
# sha256 of dbos-3.6.0-py3-none-any.whl as published on PyPI (uploaded 2026-11-17).
EXPECTED_WHEEL_SHA256 = "bed76236c8225d9da34d3f5c641dbc55249e113da071757f0d99fde6d1af58ac"
# sha256 over the sorted "path sha256=<urlsafe-b64>" lines of that wheel's RECORD
# (59 payload/metadata files; the RECORD line itself excluded).
EXPECTED_MANIFEST_SHA256 = "fee7b2fd5f8315ab57622165b9fa4d369363b51810b1955cf693a8bb54b61878"
EXPECTED_MANIFEST_ENTRIES = 59

FORBIDDEN_DISTS = re.compile(
    r"^(dbos[-_]enterprise|psycopg[-_]binary|psycopg[-_]c|psycopg2.*|opentelemetry.*|websockets)$", re.I
)
FORBIDDEN_MODULES = ("dbos_enterprise", "psycopg_binary", "psycopg_c", "psycopg2", "opentelemetry", "websockets")
TOOLING = {"pip", "setuptools", "wheel"}

failures: List[str] = []
notes: List[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"FAIL  {msg}")


def ok(msg: str) -> None:
    print(f"ok    {msg}")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def b64digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()


def check_dbos_files() -> None:
    try:
        dist = md.distribution("dbos")
    except md.PackageNotFoundError:
        fail("dbos is not installed")
        return
    if dist.version != EXPECTED_VERSION:
        fail(f"dbos version is {dist.version}, expected {EXPECTED_VERSION}")
    else:
        ok(f"dbos version {dist.version}")
    files = dist.files or []
    manifest: List[str] = []
    recorded = set()
    bad = 0
    for f in files:
        p = str(f)
        full = os.path.realpath(str(f.locate()))
        recorded.add(full)
        if p.endswith(".dist-info/RECORD"):
            continue
        if f.hash is None:
            # pip adds INSTALLER / REQUESTED / console scripts / .pyc with or without hashes
            continue
        if not os.path.isfile(full):
            fail(f"recorded file missing: {p}")
            bad += 1
            continue
        actual = b64digest(full)
        if f.hash.mode != "sha256" or actual != f.hash.value:
            fail(f"hash mismatch vs RECORD: {p}")
            bad += 1
        installer_added = (
            p.endswith((".dist-info/INSTALLER", ".dist-info/REQUESTED", ".dist-info/direct_url.json"))
            or p.startswith("..")  # ../../../bin/dbos console script
            or p.endswith(".pyc")
        )
        if not installer_added:
            manifest.append(f"{p} sha256={f.hash.value}")
    if not bad:
        ok(f"all {len(manifest)} recorded dbos files match their RECORD sha256")
    digest = hashlib.sha256("\n".join(sorted(manifest)).encode()).hexdigest()
    if digest != EXPECTED_MANIFEST_SHA256 or len(manifest) != EXPECTED_MANIFEST_ENTRIES:
        fail(f"dbos file manifest differs from the genuine 3.6.0 wheel "
             f"(entries={len(manifest)}, digest={digest})")
    else:
        ok(f"dbos file manifest equals genuine PyPI wheel {EXPECTED_WHEEL_SHA256[:12]}... ({len(manifest)} files)")
    # unrecorded files inside the package directory
    pkg_dir = os.path.realpath(str(dist.locate_file("dbos")))
    extra = []
    for root, dirs, names in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for n in names:
            full = os.path.realpath(os.path.join(root, n))
            if full not in recorded:
                extra.append(os.path.relpath(full, pkg_dir))
    if extra:
        fail(f"unrecorded files in dbos/: {extra[:10]}")
    else:
        ok("no unrecorded files inside dbos/")
    # single unpickling call site
    sites = []
    for root, dirs, names in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for n in names:
            if n.endswith((".py", ".dbos")):
                with open(os.path.join(root, n), "r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if re.search(r"pickle\.(loads?|Unpickler)\b|cPickle|\bdill\b|\bmarshal\.loads?", line):
                            sites.append(f"{os.path.relpath(os.path.join(root, n), pkg_dir)}:{i}")
    if sites != ["_serialization.py:112"]:
        fail(f"unexpected unpickling call sites in dbos: {sites}")
    else:
        ok("single unpickling call site: dbos/_serialization.py:112")


def check_absent() -> List[Tuple[str, str]]:
    dists = sorted(((norm(d.metadata["Name"]), d.version) for d in md.distributions()), key=lambda x: x[0])
    bad = [f"{n}=={v}" for n, v in dists if FORBIDDEN_DISTS.match(n)]
    if bad:
        fail(f"forbidden distributions installed: {bad}")
    else:
        ok("no dbos-enterprise / psycopg-binary / psycopg-c / psycopg2 / opentelemetry / websockets distribution")
    found = []
    for m in FORBIDDEN_MODULES:
        try:
            if importlib.util.find_spec(m) is not None:
                found.append(m)
        except (ImportError, ValueError):
            found.append(m)
    if found:
        fail(f"forbidden modules importable: {found}")
    else:
        ok("forbidden modules are not importable: " + ", ".join(FORBIDDEN_MODULES))
    return dists


def check_startup_hooks(allow_pth: List[str], allow_files: List[str]) -> None:
    dirs = set()
    try:
        dirs.update(site.getsitepackages())
    except Exception:
        pass
    try:
        dirs.add(site.getusersitepackages())
    except Exception:
        pass
    dirs.update(p for p in sys.path if p and os.path.isdir(p))
    pths, custom = [], []
    for d in sorted(dirs):
        try:
            for n in os.listdir(d):
                if n.endswith(".pth") and n not in allow_pth:
                    pths.append(os.path.join(d, n))
                if re.match(r"^(sitecustomize|usercustomize)(\.py|\.pyc|\.so|$)", n):
                    if os.path.join(d, n) in allow_files:
                        notes.append(f"start-up file allowed by --allow-file (review it): {os.path.join(d, n)}")
                    else:
                        custom.append(os.path.join(d, n))
        except OSError:
            continue
    if pths:
        fail(f".pth files present (code/paths injected at interpreter start): {pths}")
    else:
        ok(f"no .pth files in {len(dirs)} site/sys.path directories")
    if custom:
        fail(f"sitecustomize/usercustomize present: {custom}")
    else:
        ok("no sitecustomize / usercustomize")


def check_psycopg() -> None:
    try:
        import psycopg
        from psycopg import pq
    except Exception as e:
        fail(f"psycopg cannot be imported ({type(e).__name__}: {e}) -- is the system libpq installed?")
        return
    if pq.__impl__ != "python":
        fail(f"psycopg implementation is {pq.__impl__!r}, expected 'python'")
    else:
        ok(f"psycopg {psycopg.__version__} pure-Python implementation, system libpq {pq.version()} "
           f"(build {pq.__build_version__})")
    if pq.version() < 160000:
        notes.append("libpq < 16: the require_auth connection parameter is not available")


def check_lock(path: str, dists: List[Tuple[str, str]]) -> None:
    pins: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\;]+)", line.strip())
            if m:
                pins[norm(m.group(1))] = m.group(2)
    bad = []
    for n, v in dists:
        if n in TOOLING:
            continue
        if pins.get(n) != v:
            bad.append(f"{n}=={v} (lock: {pins.get(n)})")
    missing = [n for n in pins if n not in dict(dists)]
    if bad or missing:
        fail(f"installed set differs from lock: not-in-lock/wrong-version={bad} locked-but-missing={missing}")
    else:
        ok(f"installed distributions equal the lock ({len(pins)} pins)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock")
    ap.add_argument("--wheel")
    ap.add_argument("--allow-pth", action="append", default=[])
    ap.add_argument("--allow-file", action="append", default=[],
                    help="exact path of a reviewed sitecustomize/usercustomize file to tolerate")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not sys.flags.isolated:
        notes.append("not running with -I: PYTHON* variables and the user site could influence this check")
    print(f"interpreter: {sys.executable}  python {sys.version.split()[0]}  prefix {sys.prefix}")
    check_dbos_files()
    if args.wheel:
        h = hashlib.sha256(open(args.wheel, "rb").read()).hexdigest()
        if h != EXPECTED_WHEEL_SHA256:
            fail(f"wheel sha256 {h} != {EXPECTED_WHEEL_SHA256}")
        else:
            ok("wheel file sha256 matches the known-good PyPI digest")
    dists = check_absent()
    check_startup_hooks(args.allow_pth, args.allow_file)
    check_psycopg()
    if args.lock:
        check_lock(args.lock, dists)
    print("resolved distributions:")
    for n, v in dists:
        print(f"      {n}=={v}")
    for n in notes:
        print(f"note  {n}")
    if args.json:
        print(json.dumps({"ok": not failures, "failures": failures, "distributions": dict(dists)}))
    print("RESULT: " + ("PASS" if not failures else f"FAIL ({len(failures)} problem(s))"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
