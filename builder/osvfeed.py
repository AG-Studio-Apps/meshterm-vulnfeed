"""S2: the OSV release files for dpkg releases (Ubuntu and Debian). Python 3 stdlib only.

meshTerm docs/plan-host-cve-scanner.md sections 3.1-3.3 (the rules), 4.1 (the file) and 4.2 (the gates).

Pass, per OSV ecosystem zip (one read of every record):

1. Keep the affected[] entries of the configured releases (`RELEASES`). Every range must have a shape we know
   (ECOSYSTEM; alternating introduced/fixed events, optionally ending open): anything else is counted as an
   unknown shape, and any unknown shape fails the build.
2. Drop unfixed ranges (no `fixed` event: no update to offer).
3. Collect one candidate row per (release, source, introduced, fixed), merging the CVE ids of every record
   that names it (CVE records and their advisories: USN, DSA, DLA).
   Ubuntu rows also need an `availability` we know: free rows go to the release file, Ubuntu Pro rows to
   its -esm file, Livepatch / Legacy add-on / BlueField rows nowhere; an unknown value is an unknown shape.
Then, per release, with the archive Sources of every pocket and component loaded:
4. Reject nonsense fixed versions: date-shaped (UBUNTU-CVE-2024-6716's "2024-08-16"), or not a valid Debian
   version.
5. Release-baseline cut: drop fixed <= the source's release-day version (it never matches a host of that
   release). Release-day versions: Ubuntu's release pocket (frozen at release); Debian's committed
   builder/baselines/<release>.tsv, taken from snapshot.debian.org on release day (`build.py baseline`).
6. Reject a surviving fixed value whose leading numeric token matches nothing this source has had (see
   token_mismatch()). Rejected rows (4 and 6) at or over REJECT_LIMIT of an ecosystem's rows fail the build.
   Published check: the highest archive version of the source (any pocket, any component) must be >= fixed.
   Ubuntu Pro (ESM) rows skip this: the ESM archive needs a subscription token.
7. Severity, per CVE id, by the ecosystem's chain (every decision counted in the log):
   Ubuntu: Ubuntu priority, else the highest CVSS 3.x/4.0 score, else Medium.
   Debian: the highest CVSS 3.x/4.0 score, else High when a DSA/DLA ships this fix, else Medium.
   Only ids that are High or Critical stay; a row with none left is dropped.
8. Kernel fold: kernel sources become `[introduced, fixed, maxSeverity, count, publishedDate]`.
"""
import collections
import datetime
import functools
import json
import lzma
import os
import re
import time
import zipfile

import cvss
import netfetch
from dpkgver import DpkgVersion, VersionError, sort_key
from feedlib import FILE_CAP, FeedError, content_name, sha256_hex

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE_DIR = os.path.join(HERE, "baselines")
GOLDEN_DIR = os.path.join(HERE, "golden")

UBUNTU_MIRROR = "https://archive.ubuntu.com/ubuntu"
DEBIAN_MIRROR = "https://deb.debian.org/debian"
DEBIAN_SECURITY = "https://security.debian.org/debian-security"
SNAPSHOT = "https://snapshot.debian.org/archive/debian"

REJECT_LIMIT = 0.005        # rejected fixed versions, per OSV ecosystem, as a share of fixed rows
ROW_SWING = 0.30            # per-release row count change allowed against the previous build
ROW_SWING_FLOOR = 25        # ... or this many rows, whichever is larger (small files swing by single rows)
HIGH = cvss.HIGH


class Release:
    def __init__(self, key, family, ecosystem, codename, esm=False, snapshot=None):
        self.key, self.family, self.ecosystem, self.codename = key, family, ecosystem, codename
        self.esm, self.snapshot = esm, snapshot

    @property
    def osv_zip(self):
        return "Ubuntu" if self.family == "ubuntu" else "Debian"

    @property
    def base_key(self):
        """The release whose archive and baseline this one uses (the ESM files use their release's)."""
        return self.key[:-len("-esm")] if self.esm else self.key

    def suites(self):
        """[(mirror, suite)] for every pocket whose Sources count as published (plan 3.2)."""
        c = self.codename
        if self.family == "ubuntu":
            return [(UBUNTU_MIRROR, c), (UBUNTU_MIRROR, f"{c}-updates"), (UBUNTU_MIRROR, f"{c}-security")]
        return [(DEBIAN_MIRROR, c), (DEBIAN_MIRROR, f"{c}-updates"), (DEBIAN_SECURITY, f"{c}-security")]


# Ubuntu: every LTS in standard or ESM support we cover, plus the current interim (26.10; 25.10 reached end of
# life in July 2026). The ESM files hold Ubuntu:Pro:<rel> rows, for hosts with Ubuntu Pro attached (D4).
# Debian: 11 (LTS ended 2026-08-31; its rows now come from DLAs), 12, 13. Snapshot times are the first
# snapshot.debian.org run after each release's Release file was dated (11.0, 12.0, 13.0).
RELEASES = [
    Release("ubuntu-20.04", "ubuntu", "Ubuntu:20.04:LTS", "focal"),
    Release("ubuntu-22.04", "ubuntu", "Ubuntu:22.04:LTS", "jammy"),
    Release("ubuntu-24.04", "ubuntu", "Ubuntu:24.04:LTS", "noble"),
    Release("ubuntu-26.04", "ubuntu", "Ubuntu:26.04:LTS", "resolute"),
    Release("ubuntu-26.10", "ubuntu", "Ubuntu:26.10", "stonking"),
    Release("ubuntu-20.04-esm", "ubuntu", "Ubuntu:Pro:20.04:LTS", "focal", esm=True),
    Release("ubuntu-22.04-esm", "ubuntu", "Ubuntu:Pro:22.04:LTS", "jammy", esm=True),
    Release("ubuntu-24.04-esm", "ubuntu", "Ubuntu:Pro:24.04:LTS", "noble", esm=True),
    Release("ubuntu-26.04-esm", "ubuntu", "Ubuntu:Pro:26.04:LTS", "resolute", esm=True),
    Release("debian-11", "debian", "Debian:11", "bullseye", snapshot="20210815T000000Z"),
    Release("debian-12", "debian", "Debian:12", "bookworm", snapshot="20230611T000000Z"),
    Release("debian-13", "debian", "Debian:13", "trixie", snapshot="20250810T000000Z"),
]
RELEASE_KEYS = tuple(r.key for r in RELEASES)

_SOURCE_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]+$")
_DATE_SHAPED = re.compile(r"^\d{4}-\d{2}-\d{2}")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ADVISORY = re.compile(r"^(USN|DSA|DLA|DTSA)-")
_COMPONENT_PATH = re.compile(
    r"^(?:updates/)?(main|contrib|non-free|non-free-firmware|restricted|universe|multiverse)/source/Sources\.xz$")
_UBUNTU_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0}
# Ubuntu `ecosystem_specific.availability`: free rows, Pro (ESM) rows, and rows we never ship.
_AVAIL_FREE = (None, "No subscription required", "No subscription needed")
_AVAIL_PRO = ("Available with Ubuntu Pro: ", "Available with Ubuntu Pro (Infra-only): ")
_AVAIL_EXCLUDED = ("Livepatch subscription required", "Available with Ubuntu Pro with Legacy support add-on",
                   "Available for NVIDIA BlueField")
_NON_KERNEL = re.compile(r"^linux-(firmware.*|base|atm|sgx.*|tools-common|doc)$")


def is_kernel(source):
    return (source == "linux" or source.startswith("linux-")) and not _NON_KERNEL.match(source)


class ShapeError(Exception):
    pass


def range_pairs(affected):
    """[(introduced, fixed)] for one affected[] entry. Raises ShapeError on any shape we do not know."""
    ranges = affected.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise ShapeError("no ranges")
    pairs = []
    for rng in ranges:
        if not isinstance(rng, dict) or rng.get("type") != "ECOSYSTEM":
            raise ShapeError(f"range type {rng.get('type') if isinstance(rng, dict) else rng!r}")
        events = rng.get("events")
        if not isinstance(events, list) or not events:
            raise ShapeError("no events")
        introduced = None
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                raise ShapeError(f"event {event!r}")
            (kind, value), = event.items()
            if not isinstance(value, str) or not value:
                raise ShapeError(f"event value {value!r}")
            if kind == "introduced":
                if introduced is not None:
                    raise ShapeError("introduced twice without a fixed between")
                introduced = value
            elif kind == "fixed":
                if introduced is None:
                    raise ShapeError("fixed without an introduced")
                pairs.append((introduced, value))
                introduced = None
            else:
                raise ShapeError(f"event kind {kind}")
    return pairs


def leading_token(version):
    """The first digit run of the upstream part (after any epoch), or None."""
    upstream = version.split(":", 1)[1] if re.match(r"^\d+:", version) else version
    match = re.match(r"\d+", upstream)
    if not match:
        return None
    return match.group(0).lstrip("0") or "0"


def token_mismatch(fixed, version_tokens, archive_version, day_one, esm=False):
    """The leading-token sanity check (plan 3.1), or None when the fixed value looks like this source's.

    A fixed value passes when its leading numeric token is one of the record's versions[] tokens, the
    archive's or the release-day version's, or lies between the release-day and archive tokens (an upstream
    jump inside the release, such as chromium 130 between 114 and 142). ESM rows have no upper bound: the
    free archive does not see ESM's upstream jumps (clamav 1.4 for focal, whose free archive has 0.103). It
    runs only on rows that survived the baseline cut: an ancient fix (389-ds-base 1.2.x against 2.x today)
    never matches a host anyway."""
    token = leading_token(fixed)
    refs = set(version_tokens)
    for version in (archive_version, day_one):
        if version:
            refs.add(leading_token(version))
    refs.discard(None)
    if not refs or token in refs:
        return None
    low = leading_token(day_one) if day_one else None
    high = leading_token(archive_version) if archive_version else None
    if token is not None and low is not None and int(low) <= int(token) \
            and (esm or (high is not None and int(token) <= int(high))):
        return None
    return "no shared leading token"


def severity_of_record(record, counters):
    """(ubuntu priority or None, highest CVSS score or None) from a record's top-level severity[]."""
    ubuntu, best = None, None
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        kind, score = entry.get("type"), entry.get("score")
        if kind == "Ubuntu":
            value = _UBUNTU_PRIORITY.get(str(score).lower())
            if value is None:
                counters[f"ubuntu priority {str(score)[:20]!r} ignored"] += 1
            else:
                ubuntu = value if ubuntu is None else max(ubuntu, value)
        elif kind in ("CVSS_V3", "CVSS_V4"):
            try:
                value = cvss.base_score(score)
            except cvss.CVSSError:
                counters["unparseable CVSS vector"] += 1
                continue
            best = value if best is None else max(best, value)
    return ubuntu, best


class Candidate:
    __slots__ = ("ids", "advisory", "adv_date", "rec_date", "modified", "tokens", "kernel")

    def __init__(self):
        self.ids = set()
        self.advisory = False
        self.adv_date = None     # earliest advisory (USN/DSA/DLA) `published` naming this fix
        self.rec_date = None     # earliest `published` of any record naming it (fallback)
        self.modified = None     # newest `modified` of the records naming it
        self.tokens = set()


def _date(text):
    return text[:10] if isinstance(text, str) and re.match(r"^\d{4}-\d{2}-\d{2}", text) else None


def ingest(zip_path, releases, log):
    """Reads one OSV zip. Returns (candidates {release key: {(src, intro, fixed): Candidate}}, cve severity
    info {id: (ubuntu, cvss)}, stats Counter, unknown-shape examples, newest `modified`)."""
    by_eco = {r.ecosystem: r for r in releases}
    candidates = {r.key: {} for r in releases}
    info = {}
    stats = collections.Counter()
    shapes = []
    newest = None
    started = time.time()
    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            record = json.loads(archive.read(name))
            stats["records"] += 1
            modified = record.get("modified")
            key = netfetch.ts_key(modified)
            if key and (newest is None or key > newest[0]):
                newest = (key, modified)
            if record.get("withdrawn"):
                stats["withdrawn records skipped"] += 1
                continue
            rid = record.get("id", "")
            upstream = [u for u in (record.get("upstream") or []) + (record.get("aliases") or [])
                        if isinstance(u, str) and _CVE.match(u)]
            ids = sorted(set(upstream)) or [rid]
            is_adv = bool(_ADVISORY.match(rid))
            sev = severity_of_record(record, stats)
            if not is_adv:
                for cve in ids:
                    old = info.get(cve)
                    info[cve] = sev if old is None else (
                        _max_none(old[0], sev[0]), _max_none(old[1], sev[1]))
            elif rid not in info:
                info[rid] = sev
            published, modified_date = _date(record.get("published")), _date(modified)
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                release = by_eco.get(package.get("ecosystem"))
                if release is None:
                    continue
                stats[f"{release.key}: affected entries"] += 1
                source = package.get("name")
                try:
                    pairs = range_pairs(affected)
                    if not isinstance(source, str) or not _SOURCE_NAME.match(source):
                        raise ShapeError(f"source name {source!r}")
                except ShapeError as error:
                    stats[f"{release.key}: unknown range shape"] += 1
                    if len(shapes) < 10:
                        shapes.append(f"{rid} {release.ecosystem} {source}: {error}")
                    continue
                if not pairs:
                    stats[f"{release.key}: unfixed (dropped)"] += 1
                    continue
                if release.family == "ubuntu":
                    availability = (affected.get("ecosystem_specific") or {}).get("availability")
                    verdict = _availability(availability, release)
                    if verdict == "unknown":
                        stats[f"{release.key}: unknown range shape"] += 1
                        if len(shapes) < 10:
                            shapes.append(f"{rid} {release.ecosystem} {source}: availability {availability!r}")
                        continue
                    if verdict != "keep":
                        stats[f"{release.key}: excluded ({verdict})"] += len(pairs)
                        continue
                tokens = {t for t in (leading_token(v) for v in affected.get("versions") or []
                                      if isinstance(v, str)) if t}
                for introduced, fixed in pairs:
                    stats[f"{release.key}: fixed rows"] += 1
                    cand = candidates[release.key].get((source, introduced, fixed))
                    if cand is None:
                        cand = candidates[release.key][(source, introduced, fixed)] = Candidate()
                    cand.ids.update(ids)
                    cand.tokens |= tokens
                    if is_adv:
                        cand.advisory = True
                        if published and (cand.adv_date is None or published < cand.adv_date):
                            cand.adv_date = published
                    if published and (cand.rec_date is None or published < cand.rec_date):
                        cand.rec_date = published
                    if modified_date and (cand.modified is None or modified_date > cand.modified):
                        cand.modified = modified_date
    log.info(f"osv {os.path.basename(os.path.dirname(zip_path))}: {stats['records']} records read in "
             f"{time.time() - started:.0f} s")
    return candidates, info, stats, shapes, (newest[1] if newest else None)


def _max_none(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _availability(value, release):
    if value in _AVAIL_FREE:
        return "keep"
    if not isinstance(value, str):
        return "unknown"
    if value.startswith(_AVAIL_PRO):
        return "keep" if release.esm else "Ubuntu Pro only"
    if value.startswith(_AVAIL_EXCLUDED):
        return value.split(":")[0].split(" with")[0].lower()
    return "unknown"


# --- archive -------------------------------------------------------------------------------------------
def parse_release(data):
    """(Date as ISO Z, {component path: (algorithm, hex, size)}) from a Release file. SHA256 is preferred;
    newer Ubuntu Release files list only SHA512."""
    text = data.decode("utf-8", "replace")
    date = None
    files = {"sha256": {}, "sha512": {}}
    section = None
    for line in text.splitlines():
        if line.startswith("Date:"):
            date = _release_date(line[5:].strip())
        if line and not line[0].isspace():
            section = line.split(":", 1)[0]
            continue
        if section in ("SHA256", "SHA512"):
            parts = line.split()
            if len(parts) == 3 and _COMPONENT_PATH.match(parts[2]):
                files[section.lower()][parts[2]] = (section.lower(), parts[0].lower(), int(parts[1]))
    if date is None:
        raise FeedError("Release file has no Date")
    return date, files["sha256"] or files["sha512"]


def _release_date(text):
    text = " ".join(text.split())   # snapshot.ubuntu.com writes "Thu, 05 Nov 2026  3:38:05 UTC"
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            value = datetime.datetime.strptime(text.replace("UTC", "+0000"), fmt.replace("%Z", "%z"))
            return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    raise FeedError(f"bad Release Date {text!r}")


def parse_sources(handle):
    """{source: highest version text} from a Sources stream (deb822). Extra-Source-Only stanzas (old sources
    kept only for Built-Using) are skipped."""
    out = {}
    package = version = None
    extra = False

    def flush():
        if package and version and not extra:
            old = out.get(package)
            if old is None or DpkgVersion.parse(version) > DpkgVersion.parse(old):
                out[package] = version

    for raw in handle:
        line = raw.rstrip("\n")
        if not line:
            flush()
            package = version = None
            extra = False
        elif line.startswith("Package:"):
            package = line[8:].strip()
        elif line.startswith("Version:"):
            version = line[8:].strip()
        elif line.startswith("Extra-Source-Only:"):
            extra = line[18:].strip().lower() == "yes"
    flush()
    return out


def merge_max(into, other):
    for source, version in other.items():
        old = into.get(source)
        if old is None or DpkgVersion.parse(version) > DpkgVersion.parse(old):
            into[source] = version


def load_suite(cache, mirror, suite, used, log, offline=False):
    """({source: version}, Release date) for every component of one suite."""
    release_url = f"{mirror}/dists/{suite}/Release"
    release_cache = os.path.join(cache, "archive", "release", re.sub(r"[^a-z0-9.-]", "_", mirror) + "_" + suite)
    if offline:
        with open(release_cache, "rb") as handle:
            data = handle.read()
    else:
        data = netfetch.get_bytes(release_url, netfetch.RELEASE_CAP)
        os.makedirs(os.path.dirname(release_cache), exist_ok=True)
        with open(release_cache, "wb") as handle:
            handle.write(data)
    date, files = parse_release(data)
    if not files:
        raise FeedError(f"{release_url} lists no Sources.xz")
    versions = {}
    fetched = 0
    for path, (algo, digest, size) in sorted(files.items()):
        local, new = netfetch.fetch_by_hash(cache, f"{mirror}/dists/{suite}/{path}", algo, digest, size, used,
                                            offline)
        fetched += new
        with lzma.open(local, "rt", encoding="utf-8", errors="replace") as handle:
            merge_max(versions, parse_sources(handle))
    log.info(f"archive {suite}: {len(files)} component(s), {len(versions)} sources, Release {date}"
             f"{f', {fetched} downloaded' if fetched else ', all cached'}")
    return versions, date


def load_baseline_file(release):
    """({source: version}, release-day date) from builder/baselines/<release>.tsv, or (None, None)."""
    path = os.path.join(BASELINE_DIR, f"{release.key}.tsv")
    if not os.path.isfile(path):
        return None, None
    out, date = {}, None
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("# release-date "):
                date = line.split()[2]
            if not line or line.startswith("#"):
                continue
            source, version = line.split("\t")
            out[source] = version
    return out, date


def write_baseline(release, cache, log):
    """Fetches release-day Sources from snapshot.debian.org and writes builder/baselines/<release>.tsv."""
    if release.family != "debian" or not release.snapshot:
        raise FeedError(f"{release.key}: only Debian releases have a committed baseline")
    base = f"{SNAPSHOT}/{release.snapshot}"
    data = netfetch.get_bytes(f"{base}/dists/{release.codename}/Release", netfetch.RELEASE_CAP)
    date, files = parse_release(data)
    version_line = re.search(r"^Version: (\S+)$", data.decode("utf-8", "replace"), re.M)
    versions = {}
    lines = []
    for path, (algo, digest, size) in sorted(files.items()):
        local, _ = netfetch.fetch_by_hash(cache, f"{base}/dists/{release.codename}/{path}", algo, digest, size,
                                          set())
        with lzma.open(local, "rt", encoding="utf-8", errors="replace") as handle:
            merge_max(versions, parse_sources(handle))
        lines.append(f"# {path} {algo} {digest}")
    os.makedirs(BASELINE_DIR, exist_ok=True)
    out = os.path.join(BASELINE_DIR, f"{release.key}.tsv")
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(f"# Release-day source versions for {release.key} ({release.codename} "
                     f"{version_line.group(1) if version_line else '?'}), from {base}/dists/{release.codename}/\n")
        handle.write(f"# release-date {date[:10]} (Release Date {date})\n")
        handle.write("# Generated by `builder/build.py baseline`. Used for the release-baseline cut (plan 3.2).\n")
        for line in lines:
            handle.write(line + "\n")
        for source in sorted(versions):
            handle.write(f"{source}\t{versions[source]}\n")
    log.info(f"baseline {release.key}: {len(versions)} sources, Release {date} -> {out}")
    return out


# --- per-release rules ---------------------------------------------------------------------------------
def _cmp_ok(version):
    try:
        return DpkgVersion.parse(version)
    except VersionError:
        return None


def resolve(release, cands, info, archive, baseline, counters, decisions):
    """Applies rules 4-8 to one release's candidates. Returns (shipped rows for the intermediate, reject
    examples)."""
    rows = []
    examples = []
    dropped = []

    def drop(reason):
        counters[reason] += 1
        dropped.append([source, introduced, fixed, reason])

    for (source, introduced, fixed), cand in sorted(cands.items()):
        fixed_v = _cmp_ok(fixed)
        intro_ok = introduced == "0" or _cmp_ok(introduced) is not None
        reason = None
        if _DATE_SHAPED.match(fixed):
            reason = "date-shaped"
        elif fixed_v is None or not intro_ok:
            reason = "not a Debian version"
        if reason is None:
            day_one = baseline.get(source)
            if day_one is not None and fixed_v <= DpkgVersion.parse(day_one):
                drop("baseline cut")
                continue
            reason = token_mismatch(fixed, cand.tokens, archive.get(source), day_one, release.esm)
        if reason:
            counters["rejected"] += 1
            drop(f"rejected: {reason}")
            if len(examples) < 8:
                examples.append(f"{source} fixed {fixed!r} ({reason}; {', '.join(sorted(cand.ids))[:60]})")
            continue
        if not release.esm:
            published = archive.get(source)
            if published is None:
                drop("unpublished: source not in the archive")
                continue
            if DpkgVersion.parse(published) < fixed_v:
                drop("unpublished: archive below fixed")
                continue
        else:
            counters["published check skipped (ESM archive needs a token)"] += 1
        kept, best = {}, -1
        for cve in cand.ids:
            band, rule = severity(release, cve, cand, info)
            decisions[rule] += 1
            best = max(best, band)
            if band >= HIGH:
                kept[cve] = band
        if not kept:
            drop("below High (dropped)")
            dropped[-1].append(best)
            continue
        counters["shipped"] += 1
        date, date_source = (cand.adv_date, "advisory") if cand.adv_date else (cand.rec_date, "record")
        rows.append({"source": source, "introduced": introduced, "fixed": fixed,
                     "severity": max(kept.values()), "ids": sorted(kept), "kernel": is_kernel(source),
                     "date": date, "dateSource": date_source, "modified": cand.modified})
    return rows, examples, dropped


def severity(release, cve, cand, info):
    """(band, rule) for one id of one row, by the release family's chain (plan 3.2)."""
    ubuntu, score = info.get(cve, (None, None))
    if release.family == "ubuntu":
        if ubuntu is not None:
            return ubuntu, "ubuntu priority"
        if score is not None:
            return cvss.band(score), "cvss"
        return cvss.MEDIUM, "default medium"
    if score is not None:
        return cvss.band(score), "cvss"
    if cand.advisory:
        return HIGH, "dsa/dla exists -> high"
    return cvss.MEDIUM, "default medium"


def release_body(release, rows):
    """The shipped JSON object (plan 4.1)."""
    pkgs, kernel = collections.defaultdict(list), collections.defaultdict(list)
    for row in rows:
        if row["kernel"]:
            kernel[row["source"]].append([row["introduced"], row["fixed"], row["severity"], len(row["ids"]),
                                          row["date"]])
        else:
            pkgs[row["source"]].append([row["introduced"], row["fixed"], row["severity"], row["ids"]])
    order = sort_rows
    return {"release": release.key, "format": "dpkg", "keyedBy": "source",
            "pkgs": {k: order(v) for k, v in sorted(pkgs.items())},
            "kernel": {k: order(v) for k, v in sorted(kernel.items())}}


def _version_or_zero_cmp(a, b):
    """Compares two `introduced` values: "0" is below every version."""
    if a == b:
        return 0
    if a == "0":
        return -1
    if b == "0":
        return 1
    return DpkgVersion.parse(a)._cmp(DpkgVersion.parse(b))


def sort_rows(rows):
    """Rows ordered by fixed version, then introduced."""
    return sorted(rows, key=functools.cmp_to_key(
        lambda a, b: DpkgVersion.parse(a[1])._cmp(DpkgVersion.parse(b[1])) or _version_or_zero_cmp(a[0], b[0])))


_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|(USN|DSA|DLA|DTSA|LSN)-\d+(-\d+)?|(UBUNTU|DEBIAN)-CVE-\d{4}-\d{4,})$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def check_release_body(body, key, entry):
    """Raises FeedError unless a release file has the plan 4.1 shape and matches its manifest entry."""
    def fail(why):
        raise FeedError(f"{entry['file']}: {why}")
    if not isinstance(body, dict) or set(body) != {"release", "format", "keyedBy", "pkgs", "kernel"}:
        fail("keys must be release, format, keyedBy, pkgs, kernel")
    if body["release"] != key or body["format"] != entry["format"] or body["format"] != "dpkg" \
            or body["keyedBy"] != "source":
        fail("release/format/keyedBy do not match the manifest")
    count = 0
    for section, width in (("pkgs", 4), ("kernel", 5)):
        if not isinstance(body[section], dict):
            fail(f"{section} is not an object")
        for source, rows in body[section].items():
            if not _SOURCE_NAME.match(source) or (section == "kernel") != is_kernel(source):
                fail(f"bad {section} source {source!r}")
            if not isinstance(rows, list) or not rows:
                fail(f"{source}: no rows")
            for row in rows:
                count += 1
                if not isinstance(row, list) or len(row) != width:
                    fail(f"{source}: row {row!r} is not {width} fields")
                introduced, fixed, sev = row[0], row[1], row[2]
                if not (introduced == "0" or _cmp_ok(introduced)) or not isinstance(fixed, str) \
                        or _cmp_ok(fixed) is None or _DATE_SHAPED.match(fixed):
                    fail(f"{source}: bad version in {row!r}")
                if type(sev) is not int or sev not in (cvss.HIGH, cvss.CRITICAL):
                    fail(f"{source}: severity {sev!r} is not High or Critical")
                if section == "pkgs":
                    ids = row[3]
                    if not isinstance(ids, list) or not ids or ids != sorted(set(ids)) \
                            or not all(isinstance(i, str) and _ID.match(i) for i in ids):
                        fail(f"{source}: bad ids {ids!r}")
                else:
                    if type(row[3]) is not int or row[3] < 1 or not (row[4] is None or (
                            isinstance(row[4], str) and _DAY.match(row[4]))):
                        fail(f"{source}: bad kernel row {row!r}")
    if count != entry["rows"]:
        fail(f"{count} rows, the manifest says {entry['rows']}")


def body_bytes(body):
    return (json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def row_count(body):
    return sum(len(v) for v in body["pkgs"].values()) + sum(len(v) for v in body["kernel"].values())


# --- golden fixtures -----------------------------------------------------------------------------------
def read_inventory(path):
    """{source: source version} from a `dpkg-query` TSV (status, binary, version, source, source version) or a
    reduced `source<TAB>version` TSV. Only installed (`ii`/`hi`) rows count; `#` lines are comments."""
    out = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) == 5:
                if parts[0].strip() not in ("ii", "hi"):
                    continue
                source, version = parts[3], parts[4]
            elif len(parts) == 2:
                source, version = parts
            else:
                raise FeedError(f"{os.path.basename(path)}: bad line {line[:60]!r}")
            old = out.get(source)
            if old is None or DpkgVersion.parse(version) > DpkgVersion.parse(old):
                out[source] = version
    return out


def published_before(row, capture):
    """True when this row's fix date (the earliest advisory naming it, else the earliest record) is before the
    capture date."""
    return bool(row["date"]) and row["date"] < capture


def golden_hits(rows, inventory, capture, at_capture=None):
    """{source: [fixed, ...]} for non-kernel rows published before `capture` that the inventory is below.
    With `at_capture` ({source: highest archive version at the capture time}), a row also needs its fix to
    have been in the archive then, which keeps a frozen fixture from drifting when OSV later records an old
    CVE's fix."""
    hits = collections.defaultdict(list)
    for row in rows:
        if row["kernel"] or not published_before(row, capture):
            continue
        installed = inventory.get(row["source"])
        if installed is None:
            continue
        fixed = DpkgVersion.parse(row["fixed"])
        if at_capture is not None:
            then = at_capture.get(row["source"])
            if then is None or DpkgVersion.parse(then) < fixed:
                continue
        have = DpkgVersion.parse(installed)
        if row["introduced"] != "0" and have < DpkgVersion.parse(row["introduced"]):
            continue
        if have < fixed:
            hits[row["source"]].append(row["fixed"])
    return dict(hits)


def snapshot_suites(release, stamp):
    """The release's suites on snapshot.ubuntu.com / snapshot.debian.org at `stamp` (YYYYMMDDTHHMMSSZ)."""
    c = release.codename
    if release.family == "ubuntu":
        base = f"https://snapshot.ubuntu.com/ubuntu/{stamp}"
        return [(base, c), (base, f"{c}-updates"), (base, f"{c}-security")]
    return [(f"{SNAPSHOT}/{stamp}", c), (f"{SNAPSHOT}/{stamp}", f"{c}-updates"),
            (f"https://snapshot.debian.org/archive/debian-security/{stamp}", f"{c}-security")]


def write_golden_archive(case, cache, log, golden_dir=GOLDEN_DIR):
    """Writes the case's `archive` file: the highest version, at `archiveAt`, of every source in the fixture,
    across the release's pockets on the distro's snapshot service."""
    release = next(r for r in RELEASES if r.key == case["release"])
    inventory = read_inventory(os.path.join(golden_dir, case["fixture"]))
    merged, header = {}, []
    for mirror, suite in snapshot_suites(release, case["archiveAt"]):
        versions, date = load_suite(cache, mirror, suite, set(), log)
        merge_max(merged, versions)
        header.append(f"# {mirror}/dists/{suite}/ Release {date}")
    out = os.path.join(golden_dir, case["archive"])
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(f"# Archive versions at {case['archiveAt']} for the sources in {case['fixture']} "
                     f"({release.key}). Generated by `builder/build.py golden-archive`.\n")
        for line in header:
            handle.write(line + "\n")
        for source in sorted(inventory):
            if source in merged:
                handle.write(f"{source}\t{merged[source]}\n")
    log.info(f"golden archive {case['archive']}: {sum(1 for s in inventory if s in merged)} of {len(inventory)} "
             f"sources at {case['archiveAt']}")
    return out


def check_golden(rows_by_release, log, golden_dir=GOLDEN_DIR):
    """Runs builder/golden/expected.json. Raises FeedError on a miss."""
    with open(os.path.join(golden_dir, "expected.json"), encoding="utf-8") as handle:
        spec = json.load(handle)
    failures = []
    for case in spec["cases"]:
        rows = rows_by_release.get(case["release"])
        if rows is None:
            failures.append(f"{case['fixture']}: release {case['release']} was not built")
            continue
        inventory = read_inventory(os.path.join(golden_dir, case["fixture"]))
        at_capture = read_inventory(os.path.join(golden_dir, case["archive"])) if case.get("archive") else None
        hits = golden_hits(rows, inventory, case["capture"], at_capture)
        got = sorted(hits)
        detail = ", ".join(f"{s} {inventory[s]} < {max(hits[s], key=sort_key)}" for s in got) or "none"
        if "exact" in case and got != sorted(case["exact"]):
            failures.append(f"{case['fixture']} ({case['release']}): hits {got}, expected exactly "
                            f"{sorted(case['exact'])} [{detail}]")
        elif "atLeast" in case and not set(case["atLeast"]) <= set(got):
            failures.append(f"{case['fixture']} ({case['release']}): missing "
                            f"{sorted(set(case['atLeast']) - set(got))} [{detail}]")
        else:
            log.info(f"golden {case['fixture']} ({case['release']}, before {case['capture']}): "
                     f"{len(got)} source(s) flagged: {detail}")
    if failures:
        raise FeedError("golden fixtures: " + "; ".join(failures))


# --- the stage -----------------------------------------------------------------------------------------
def check_row_swing(releases_out, previous, log):
    """+-ROW_SWING (or ROW_SWING_FLOOR rows) against the previous build's manifest; a first build passes."""
    if previous is None:
        log.info("row-count gate: no previous build with releases; first build allowed")
        return
    problems = []
    for key, entry in sorted(releases_out.items()):
        old = (previous.get(key) or {}).get("rows")
        if old is None:
            log.info(f"row-count gate: {key} is new ({entry['rows']} rows), allowed")
            continue
        allowed = max(old * ROW_SWING, ROW_SWING_FLOOR)
        if abs(entry["rows"] - old) > allowed:
            problems.append(f"{key} {old} -> {entry['rows']} rows (allowed +-{allowed:.0f})")
    gone = sorted(set(previous) - set(releases_out))
    if gone:
        problems.append(f"release(s) missing since the previous build: {gone}")
    if problems:
        raise FeedError("row-count gate: " + "; ".join(problems))
    log.info("row-count gate: pass")


def build_releases(site_v1, log, cache, work, previous=None, offline=False, releases=RELEASES,
                   golden_dir=GOLDEN_DIR):
    """Writes v1/r/<release>-<sha16>.json for every release; returns (releases, sources) for the manifest.

    `previous` is the previous build's manifest `releases` (None for the first build). Intermediates (every
    shipped row with its publish date, and the counters) go to `work`/<release>.rows.json."""
    started = time.time()
    os.makedirs(os.path.join(site_v1, "r"), exist_ok=True)
    os.makedirs(work, exist_ok=True)
    sources = {"osv": {}, "archive": {}, "baseline": {}}
    used = set()

    archives, baselines = {}, {}
    for release in releases:
        if release.esm or release.key in archives:
            continue
        merged, release_pocket = {}, None
        for mirror, suite in release.suites():
            versions, date = load_suite(cache, mirror, suite, used, log, offline)
            sources["archive"][suite] = date
            merge_max(merged, versions)
            if suite == release.codename:
                release_pocket = (versions, date)
        archives[release.key] = merged
        if release.family == "ubuntu":
            baselines[release.key] = release_pocket[0]
            sources["baseline"][release.key] = release_pocket[1][:10]
        else:
            data, day = load_baseline_file(release)
            if data is None:
                raise FeedError(f"{release.key}: builder/baselines/{release.key}.tsv is missing "
                                "(run `builder/build.py baseline`)")
            baselines[release.key] = data
            sources["baseline"][release.key] = day
    if not offline:
        netfetch.prune_by_hash(cache, used, log)

    out, rows_by_release, unknown = {}, {}, []
    for zip_name in sorted({r.osv_zip for r in releases}):
        members = [r for r in releases if r.osv_zip == zip_name]
        zip_path = netfetch.fetch_osv_zip(cache, zip_name, log, offline)
        candidates, info, stats, shapes, newest = ingest(zip_path, members, log)
        if newest:
            netfetch.record_highwater(cache, zip_name, newest)
            sources["osv"][zip_name] = netfetch.ts_seconds(newest)
        for key, value in sorted(stats.items()):
            if ":" not in key:
                log.info(f"osv {zip_name}: {key} {value}")
        zip_fixed = zip_rejected = 0
        for release in members:
            counters, decisions = collections.Counter(), collections.Counter()
            base = release.base_key
            rows, examples, dropped = resolve(release, candidates[release.key], info, archives[base],
                                              baselines[base], counters, decisions)
            fixed_rows = len(candidates[release.key])
            zip_fixed += fixed_rows
            zip_rejected += counters["rejected"]
            body = release_body(release, rows)
            data = body_bytes(body)
            if len(data) > FILE_CAP:
                raise FeedError(f"{release.key}: {len(data)} bytes, over the {FILE_CAP}-byte cap")
            name = "r/" + content_name(release.key, data)
            with open(os.path.join(site_v1, name), "wb") as handle:
                handle.write(data)
            out[release.key] = {"format": "dpkg", "file": name, "sha256": sha256_hex(data), "bytes": len(data),
                                "rows": row_count(body)}
            rows_by_release[release.key] = rows
            shape_count = stats[f"{release.key}: unknown range shape"]
            if shape_count:
                unknown.append(f"{release.key}: {shape_count}")
            summary = {k.split(": ", 1)[1]: v for k, v in stats.items() if k.startswith(release.key + ": ")}
            log.info(f"{release.key}: {fixed_rows} distinct fixed rows; "
                     + ", ".join(f"{k} {v}" for k, v in sorted(counters.items()) if not k.startswith("rejected:"))
                     + f"; {out[release.key]['rows']} rows, {len(data)} bytes -> {name}")
            log.info(f"{release.key}: severity decisions (per id): "
                     + (", ".join(f"{k} {v}" for k, v in sorted(decisions.items())) or "none"))
            log.info(f"{release.key}: osv entries: " + ", ".join(f"{k} {v}" for k, v in sorted(summary.items())))
            if counters["rejected"]:
                log.info(f"{release.key}: rejected {counters['rejected']} ("
                         + ", ".join(f"{k[10:]} {v}" for k, v in sorted(counters.items())
                                     if k.startswith("rejected: ")) + "), e.g. " + "; ".join(examples[:4]))
            kernels = sorted({r["source"] for r in rows if r["kernel"]})
            if kernels:
                log.info(f"{release.key}: kernel sources folded ({len(kernels)}): {' '.join(kernels)}")
            with open(os.path.join(work, f"{release.key}.rows.json"), "w", encoding="utf-8") as handle:
                json.dump({"release": release.key, "counters": counters, "decisions": decisions,
                           "osv": summary, "rows": rows, "dropped": dropped}, handle, indent=0, sort_keys=True)
        share = zip_rejected / zip_fixed if zip_fixed else 0.0
        log.info(f"osv {zip_name}: rejected {zip_rejected} of {zip_fixed} fixed rows ({share:.3%})")
        if share >= REJECT_LIMIT:
            raise FeedError(f"osv {zip_name}: {share:.2%} of fixed versions rejected, the limit is "
                            f"{REJECT_LIMIT:.1%}")
        if shapes:
            log.info(f"osv {zip_name}: unknown shapes, e.g. " + "; ".join(shapes[:5]))
    if unknown:
        raise FeedError("unknown range shapes (fail closed): " + ", ".join(unknown))
    check_golden(rows_by_release, log, golden_dir)
    check_row_swing(out, previous, log)
    log.info(f"releases: {len(out)} built in {time.time() - started:.0f} s")
    return out, sources
