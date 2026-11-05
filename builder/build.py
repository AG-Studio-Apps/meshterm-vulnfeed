#!/usr/bin/env python3
"""Builds the vulnfeed site: out/v1/manifest.json plus its content-addressed files. Python 3 stdlib only.

    build.py build --commit SHA [--out out] [--record record/build.json] [--now 2026-11-05T05:10:00Z]
                   [--live-manifest FILE] [--carry-base URL_OR_DIR]
    build.py gate  [--out out]

`build` writes, under --out (the Pages site root):
    v1/manifest.json                 the only signed file (scripts/sign.py, or the CI sign job, signs it)
    v1/curated-<sha256-16>.json      a byte copy of curated/curated.json, once it validates
    v1/r/<release>-<sha256-16>.json  S2 (OSV release files); none in S1
plus the files of the previous KEEP_BUILDS - 1 builds (read from builds/<serial>.json, fetched from
--carry-base and checked against their recorded sha256), so a device holding an older manifest can still
fetch what it names. It ends with the gate, and writes --record: the build log that CI commits as
builds/<serial>.json (outside the site).

Serial = max(the highest builds/<serial>.json, the live manifest's serial) + 1. The live floor matters when
a signed build was deployed but its builds/ commit failed: reusing that serial with different bytes would
make every device refuse the feed (same version, different body).
"""
import argparse
import datetime
import os
import re
import shutil
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feedlib import (FILE_CAP, FILE_RE, GENERATED_RE, KEEP_BUILDS, MANIFEST_CAP, MANIFEST_SCHEMA,  # noqa: E402
                     FeedError, content_name, dumps, is_int, loads_strict, sha256_hex)
import validate_curated  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
MANIFEST_KEYS = {"schema", "version", "serial", "generated", "sources", "releases", "curated"}
RELEASE_KEYS = {"format", "file", "sha256", "bytes", "rows"}
RELEASE_FORMATS = ("dpkg", "apk", "rpm")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# A live serial this far above the builds/ history is not a missed commit; stop and look.
MAX_LIVE_LEAD = 100


class Log:
    def __init__(self, echo=True):
        self.lines, self.warnings, self.echo = [], [], echo

    def info(self, text):
        self.lines.append(text)
        if self.echo:
            print(text)

    def warn(self, text):
        self.warnings.append(text)
        self.lines.append(f"WARNING: {text}")
        if self.echo:
            print(f"::warning::{text}")


# --- S2 seam -------------------------------------------------------------------------------------------
def build_releases(site_v1, log):
    """S2: the OSV builder. Returns (releases, sources) for the manifest.

    `releases` maps a release key (`ubuntu-24.04`, `debian-12`, ...) to
    {"format": "dpkg"|"apk"|"rpm", "file": "r/<release>-<sha256-16>.json", "sha256": <hex>, "bytes": N,
     "rows": N}, each file written under site_v1/r/ with feedlib.content_name(). `sources` records the OSV
    high-water time and the archive Sources dates (plan 4.1/4.2). S2 also adds its gates here: per-release
    row counts within +-30% of the previous build, rejected versions under 0.5%, unknown range shapes = 0,
    and the golden fixtures.

    S1 is curated-only: no release files, empty `releases` and `sources`.
    """
    log.info("releases: none (S1 is curated-only; the OSV builder is S2)")
    return {}, {}


# --- history -------------------------------------------------------------------------------------------
def history(builds_dir):
    """[(serial, record)] for builds/<serial>.json, highest first."""
    out = []
    if not os.path.isdir(builds_dir):
        return out
    for name in os.listdir(builds_dir):
        match = re.fullmatch(r"([1-9][0-9]*)\.json", name)
        if not match:
            continue
        with open(os.path.join(builds_dir, name), "rb") as handle:
            record = loads_strict(handle.read())
        serial = int(match.group(1))
        if not isinstance(record, dict) or record.get("serial") != serial:
            raise FeedError(f"builds/{name} does not record serial {serial}")
        out.append((serial, record))
    out.sort(key=lambda pair: pair[0], reverse=True)
    return out


def next_serial(past, live_manifest, log):
    top = past[0][0] if past else 0
    live = 0
    if live_manifest is not None:
        serial = live_manifest.get("serial") if isinstance(live_manifest, dict) else None
        if not is_int(serial) or serial < 1:
            raise FeedError("the live manifest has no positive integer serial")
        live = serial
        if live > top + MAX_LIVE_LEAD:
            raise FeedError(f"the live serial {live} is more than {MAX_LIVE_LEAD} above builds/ ({top}); "
                            "something other than this pipeline published, investigate before building")
        if live > top:
            log.warn(f"the live serial {live} is above builds/ ({top}): an earlier builds/ commit was lost")
    serial = max(top, live) + 1
    log.info(f"serial {serial} (builds/ high-water {top}, live {live or 'none'})")
    return serial


def referenced_files(manifest):
    """{relative path: sha256} a manifest names."""
    files = {}
    curated = manifest.get("curated") or {}
    if curated.get("file"):
        files[curated["file"]] = curated.get("sha256")
    for entry in (manifest.get("releases") or {}).values():
        files[entry["file"]] = entry["sha256"]
    return files


def _fetch(base, rel):
    if re.match(r"^https?://", base) or base.startswith("file://"):
        url = f"{base.rstrip('/')}/v1/{rel}"
        request = urllib.request.Request(url, headers={"User-Agent": "meshterm-vulnfeed-builder"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(FILE_CAP + 1)
    else:
        with open(os.path.join(base, "v1", rel), "rb") as handle:
            data = handle.read(FILE_CAP + 1)
    if len(data) > FILE_CAP:
        raise FeedError(f"{rel} is larger than {FILE_CAP} bytes")
    return data


def carry_previous(past, site_v1, carry_base, log):
    """Copy the files of the previous KEEP_BUILDS - 1 builds into the site. A miss is a warning: the newest
    manifest names only this build's files, and a device on an older one refetches the manifest."""
    carried = []
    for serial, record in past[:KEEP_BUILDS - 1]:
        for rel, sha in sorted(referenced_files(record.get("manifest") or {}).items()):
            if not FILE_RE.fullmatch(rel) or not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                log.warn(f"builds/{serial}.json names a bad file {rel!r}; not carried")
                continue
            dest = os.path.join(site_v1, rel)
            if os.path.exists(dest):
                continue
            if not carry_base:
                log.warn(f"{rel} (serial {serial}) not carried: no --carry-base")
                continue
            try:
                data = _fetch(carry_base, rel)
            except (OSError, urllib.error.URLError, FeedError) as error:
                log.warn(f"{rel} (serial {serial}) not carried: {error}")
                continue
            if sha256_hex(data) != sha:
                log.warn(f"{rel} (serial {serial}) not carried: sha256 does not match builds/{serial}.json")
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(data)
            carried.append(rel)
            log.info(f"carried {rel} from serial {serial}")
    return carried


# --- gate ----------------------------------------------------------------------------------------------
def check_manifest(manifest):
    """Raise FeedError unless the manifest has schema 1's exact shape."""
    if not isinstance(manifest, dict):
        raise FeedError("the manifest is not an object")
    if set(manifest) != MANIFEST_KEYS:
        raise FeedError(f"manifest keys {sorted(manifest)} != {sorted(MANIFEST_KEYS)}")
    if manifest["schema"] != MANIFEST_SCHEMA or not is_int(manifest["schema"]):
        raise FeedError(f"schema must be {MANIFEST_SCHEMA}")
    if not is_int(manifest["serial"]) or manifest["serial"] < 1:
        raise FeedError("serial must be a positive integer")
    if manifest["version"] != manifest["serial"] or not is_int(manifest["version"]):
        raise FeedError("version must equal serial (the app's verifier reads `version`)")
    generated = manifest["generated"]
    if not isinstance(generated, str) or not GENERATED_RE.fullmatch(generated):
        raise FeedError("generated must be UTC ISO 8601 like 2026-11-05T05:10:00Z")
    datetime.datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(manifest["sources"], dict):
        raise FeedError("sources must be an object")
    releases = manifest["releases"]
    if not isinstance(releases, dict):
        raise FeedError("releases must be an object")
    for key, entry in releases.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,40}", key):
            raise FeedError(f"bad release key {key!r}")
        if not isinstance(entry, dict) or set(entry) != RELEASE_KEYS:
            raise FeedError(f"release {key}: keys must be {sorted(RELEASE_KEYS)}")
        if entry["format"] not in RELEASE_FORMATS:
            raise FeedError(f"release {key}: format must be one of {RELEASE_FORMATS}")
        if not isinstance(entry["file"], str) or not FILE_RE.fullmatch(entry["file"]) \
                or not entry["file"].startswith(f"r/{key}-"):
            raise FeedError(f"release {key}: bad file name {entry['file']!r}")
        if not isinstance(entry["sha256"], str) or not SHA_RE.fullmatch(entry["sha256"]):
            raise FeedError(f"release {key}: bad sha256")
        for count in ("bytes", "rows"):
            if not is_int(entry[count]) or entry[count] < 0:
                raise FeedError(f"release {key}: {count} must be a non-negative integer")
    curated = manifest["curated"]
    if not isinstance(curated, dict) or set(curated) != {"file", "sha256"}:
        raise FeedError("curated must be {file, sha256}")
    if not isinstance(curated["file"], str) or not re.fullmatch(r"curated-[0-9a-f]{16}\.json", curated["file"]):
        raise FeedError(f"bad curated file name {curated['file']!r}")
    if not isinstance(curated["sha256"], str) or not SHA_RE.fullmatch(curated["sha256"]) \
            or not curated["file"].startswith(f"curated-{curated['sha256'][:16]}"):
        raise FeedError("curated sha256 is malformed or does not match its file name")


def gate(out_dir, log):
    """Checks a built site before anything signs it. Raises FeedError."""
    site_v1 = os.path.join(out_dir, "v1")
    path = os.path.join(site_v1, "manifest.json")
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) > MANIFEST_CAP:
        raise FeedError(f"manifest.json is {len(raw)} bytes, at most {MANIFEST_CAP}")
    manifest = loads_strict(raw)
    check_manifest(manifest)
    if dumps(manifest) != raw:
        raise FeedError("manifest.json is not in the builder's canonical form")
    sizes = {entry["file"]: entry["bytes"] for entry in manifest["releases"].values()}
    for rel, sha in referenced_files(manifest).items():
        file_path = os.path.join(site_v1, rel)
        if not os.path.isfile(file_path) or os.path.islink(file_path):
            raise FeedError(f"manifest names {rel}, which is not in the site")
        with open(file_path, "rb") as handle:
            data = handle.read()
        if sha256_hex(data) != sha:
            raise FeedError(f"{rel}: sha256 does not match the manifest")
        if rel in sizes and sizes[rel] != len(data):
            raise FeedError(f"{rel}: {len(data)} bytes, the manifest says {sizes[rel]}")
    with open(os.path.join(site_v1, manifest["curated"]["file"]), "rb") as handle:
        validate_curated.load_and_validate(handle.read())
    total = 0
    for root, dirs, files in os.walk(out_dir):
        for name in dirs + files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                raise FeedError(f"{os.path.relpath(full, out_dir)} is a symlink")
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, site_v1)
            size = os.path.getsize(full)
            total += size
            if size > FILE_CAP:
                raise FeedError(f"{os.path.relpath(full, out_dir)} is {size} bytes, at most {FILE_CAP}")
            if root.startswith(site_v1) and rel not in ("manifest.json", "manifest.json.minisig") and not FILE_RE.fullmatch(rel):
                raise FeedError(f"unexpected file v1/{rel}")
    log.info(f"gate: pass (serial {manifest['serial']}, {len(raw)} byte manifest, {total} bytes in the site)")
    return manifest


# --- build ---------------------------------------------------------------------------------------------
def build(repo_root, out_dir, commit, now, live_manifest=None, carry_base=None, log=None):
    log = log or Log(echo=False)
    if not COMMIT_RE.fullmatch(commit):
        raise FeedError("--commit must be a 40-hex commit id")
    if not GENERATED_RE.fullmatch(now):
        raise FeedError("--now must be UTC ISO 8601 like 2026-11-05T05:10:00Z")
    past = history(os.path.join(repo_root, "builds"))
    serial = next_serial(past, live_manifest, log)

    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    site_v1 = os.path.join(out_dir, "v1")
    os.makedirs(site_v1)
    with open(os.path.join(out_dir, ".nojekyll"), "wb"):
        pass

    with open(os.path.join(repo_root, "curated", "curated.json"), "rb") as handle:
        curated_bytes = handle.read()
    curated_doc = validate_curated.load_and_validate(curated_bytes)
    curated_name = content_name("curated", curated_bytes)
    with open(os.path.join(site_v1, curated_name), "wb") as handle:
        handle.write(curated_bytes)
    log.info(f"curated: {len(curated_doc['rules'])} rule(s) -> {curated_name}")

    releases, sources = build_releases(site_v1, log)

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "version": serial,
        "serial": serial,
        "generated": now,
        "sources": sources,
        "releases": releases,
        "curated": {"file": curated_name, "sha256": sha256_hex(curated_bytes)},
    }
    with open(os.path.join(site_v1, "manifest.json"), "wb") as handle:
        handle.write(dumps(manifest))

    carried = carry_previous(past, site_v1, carry_base, log)
    gate(out_dir, log)
    record = {
        "serial": serial,
        "commit": commit,
        "manifest": manifest,
        "carried": carried,
        "log": log.lines,
        "warnings": log.warnings,
    }
    return manifest, record


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--repo-root", default=REPO_ROOT)
    b.add_argument("--out", default="out")
    b.add_argument("--record", default=os.path.join("record", "build.json"))
    b.add_argument("--commit", required=True)
    b.add_argument("--now", default=None)
    b.add_argument("--live-manifest", help="the live manifest.json (fetched by CI), for the serial floor")
    b.add_argument("--carry-base", help="site root (URL or directory) to carry the previous builds' files from")
    g = sub.add_parser("gate")
    g.add_argument("--out", default="out")
    args = parser.parse_args(argv)

    log = Log()
    try:
        if args.command == "gate":
            gate(args.out, log)
            return 0
        live = None
        if args.live_manifest:
            with open(args.live_manifest, "rb") as handle:
                live = loads_strict(handle.read())
        manifest, record = build(args.repo_root, args.out, args.commit, args.now or utc_now(),
                                 live, args.carry_base, log)
    except (OSError, FeedError, ValueError) as error:
        print(f"::error::build failed: {error}", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.record)), exist_ok=True)
    with open(args.record, "wb") as handle:
        handle.write(dumps(record))
    print(f"built serial {manifest['serial']} ({manifest['generated']}); record at {args.record}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
