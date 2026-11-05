"""S2 + S4: the OSV release files for dpkg releases (Ubuntu and Debian) and apk releases (Alpine). Python 3
stdlib only.

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
   Ubuntu: the package's own Ubuntu priority (affected[].ecosystem_specific.ubuntu_priority), else the
   record's, else the highest CVSS 3.x/4.0 score, else Medium.
   Debian: the highest CVSS 3.x/4.0 score, else High when a DSA/DLA that names this id ships this fix, else
   Medium.
   Only ids that are High or Critical stay; a row with none left is dropped.
8. Kernel fold: kernel sources become `[introduced, fixed, maxSeverity, count, publishedDate]`.

Alpine (S4, format "apk", keyed by ORIGIN) takes the same pass with these differences:
1. A range with a not-affected marker (fixed "0" / "0-r0") is dropped whole and counted. Each `introduced` is
   normalised (1a): an upstream X.Y.Z-N (ImageMagick 7.0.0-0) becomes the dotted X.Y.Z.N aports writes, any
   other unparseable value (a date) becomes "0"; both are counted, and the "0" kind is gated
   (INTRODUCED_REJECT_LIMIT). A fixed value apk cannot order is taken out of the walk and kept as a pair of its
   own for resolve() to reject. The remaining events are sorted by apk version ("0" lowest) and walked as OSV
   does: introduced opens, fixed closes; each (introduced, the FIRST fixed after it) is one row (OSV parity:
   postgresql17 CVE-2026-2006 [0, 17.8-r0, 17.9-r0] is affected below 17.8-r0 only). A fixed with no open
   introduced (the 2nd/3rd fixed of [0, f1, f2, f3], or a fixed below its introduced) is dropped and counted,
   not a failure.
4. A fixed value that is date-shaped or not a valid apk version (builder/apkver.py) is rejected (the same
   REJECT_LIMIT gate).
5, 6. No baseline cut, no leading-token check and no published check: Alpine fixes come from secdb, built
   from the branch's aports secfixes (so a fix is in that branch's repository), and there is no
   release-day archive to cut against. APKINDEX is RSA-signed, which the stdlib cannot verify.
7. Severity: the highest CVSS 3.x/4.0 score, else Medium.
8. Kernel origins (APK_KERNELS) fold with a null publishedDate: OSV Alpine has no fix date (a record's
   `published` is the CVE's NVD date, older than the fix), and the app never counts a pending kernel restart
   from a null date.
"""
import collections
import datetime
import functools
import json
import lzma
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

import apkver
import cvss
import netfetch
from dpkgver import DpkgVersion, VersionError, sort_key
from feedlib import FILE_CAP, FeedError, content_name, sha256_hex

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE_DIR = os.path.join(HERE, "baselines")
GOLDEN_DIR = os.path.join(HERE, "golden")
# The distro archive keyrings, pinned in the repo (keys/archive/README.md says where each came from). Every
# suite's InRelease must carry at least one valid signature from its family's keyring and no bad one (apt's
# rule), checked with gpgv; only then are its Sources.xz digests trusted.
ARCHIVE_KEYRINGS = {
    "ubuntu": os.path.join(HERE, "..", "keys", "archive", "ubuntu-archive-keyring.gpg"),
    "debian": os.path.join(HERE, "..", "keys", "archive", "debian-archive-keyring.gpg"),
}

UBUNTU_MIRROR = "https://archive.ubuntu.com/ubuntu"
DEBIAN_MIRROR = "https://deb.debian.org/debian"
DEBIAN_SECURITY = "https://security.debian.org/debian-security"
SNAPSHOT = "https://snapshot.debian.org/archive/debian"

REJECT_LIMIT = 0.005        # rejected fixed versions, per OSV ecosystem, as a share of fixed rows
# Alpine `introduced` values that are neither an apk version nor an upstream X.Y.Z-N (dates: libdwarf
# 1999-12-14, jq 2026-04-02) are read as "0" (normalise_apk_introduced), which WIDENS their range; that kind is
# gated on its own, as a share of the zip's fixed range events. The X.Y.Z-N kind (ImageMagick 7.0.0-0, 104 of
# 17,856 rows on 2026-11-05) is normalised to the dotted form aports uses and is only counted.
INTRODUCED_REJECT_LIMIT = 0.02
ROW_SWING = 0.30            # per-release row count change allowed against the previous build
ROW_SWING_FLOOR = 25        # ... or this many rows, whichever is larger (small files swing by single rows)
HIGH = cvss.HIGH


_OSV_ZIPS = {"ubuntu": "Ubuntu", "debian": "Debian", "alpine": "Alpine"}


class Release:
    def __init__(self, key, family, ecosystem, codename, esm=False, snapshot=None):
        self.key, self.family, self.ecosystem, self.codename = key, family, ecosystem, codename
        self.esm, self.snapshot = esm, snapshot

    @property
    def osv_zip(self):
        return _OSV_ZIPS[self.family]

    @property
    def format(self):
        """The manifest `format`: "apk" for Alpine, "dpkg" for Ubuntu and Debian."""
        return "apk" if self.family == "alpine" else "dpkg"

    @property
    def has_archive(self):
        """Whether the release has a Sources archive (and a baseline) to load. Alpine has neither (S4)."""
        return self.family != "alpine"

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
    # Alpine 3.20+ (plan 3.4). 3.20 (EOL 2026-04-01) and 3.21 (EOL 2026-11-01) are past end of life per
    # alpinelinux.org/releases.json; kept for now (their hosts still exist), dropping them is open.
    Release("alpine-3.20", "alpine", "Alpine:v3.20", None),
    Release("alpine-3.21", "alpine", "Alpine:v3.21", None),
    Release("alpine-3.22", "alpine", "Alpine:v3.22", None),
    Release("alpine-3.23", "alpine", "Alpine:v3.23", None),
    Release("alpine-3.24", "alpine", "Alpine:v3.24", None),
]
RELEASE_KEYS = tuple(r.key for r in RELEASES)

_SOURCE_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]+$")
# Alpine origin names also use `_` (wpa_supplicant, mini_httpd, sdl2_image).
_ORIGIN_NAME = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
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


# Alpine kernel origins. NOT linux-pam (userspace PAM), linux-headers, linux-firmware*, linux-tools.
APK_KERNELS = frozenset({"linux-lts", "linux-edge", "linux-rpi", "linux-virt", "linux-stable"})


def is_kernel(source, fmt="dpkg"):
    if fmt == "apk":
        return source in APK_KERNELS
    return (source == "linux" or source.startswith("linux-")) and not _NON_KERNEL.match(source)


def name_ok(source, fmt="dpkg"):
    return isinstance(source, str) and bool((_ORIGIN_NAME if fmt == "apk" else _SOURCE_NAME).match(source))


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


def _event_list(rng):
    """[(kind, value)] of one range, after the checks every family shares."""
    if not isinstance(rng, dict) or rng.get("type") != "ECOSYSTEM":
        raise ShapeError(f"range type {rng.get('type') if isinstance(rng, dict) else rng!r}")
    events = rng.get("events")
    if not isinstance(events, list) or not events:
        raise ShapeError("no events")
    out = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ShapeError(f"event {event!r}")
        (kind, value), = event.items()
        if not isinstance(value, str) or not value:
            raise ShapeError(f"event value {value!r}")
        if kind not in ("introduced", "fixed"):
            raise ShapeError(f"event kind {kind}")
        out.append((kind, value))
    return out


def _apk_event_key(event):
    kind, value = event
    return (0, 0) if kind == "introduced" and value == "0" else (1, apkver.sort_key(value))


# Not-affected markers: a range whose fixed is "0" / "0-r0" says the package never had the bug (secdb lists a
# CVE with fix "0" for a branch that was never affected). Such a range is dropped whole and counted.
NOT_AFFECTED_FIXED = ("0", "0-r0")
# OSV Alpine `introduced` values apk cannot parse (rule 1a of the Alpine notes): an upstream `X.Y.Z-N` (ImageMagick
# 7.0.0-0, 6.9.10-54; go 1.21.0-0) is the same version aports writes dotted (imagemagick 7.1.2.15-r0), so it is
# normalised to that; anything else (libdwarf 1999-12-14, jq 2026-04-02: dates, not versions) becomes "0".
_UPSTREAM_DASHED = re.compile(r"^\d+(\.\d+)*-\d+$")
INTRO_NORMALISED = "introduced normalised (X.Y.Z-N -> X.Y.Z.N)"
INTRO_ZEROED = "introduced unparseable -> 0"
NOT_AFFECTED = "not-affected range (fixed 0) dropped"
BAD_FIXED = "bad fixed event kept apart (range walked without it)"


def _apk_ok(value):
    return apkver.validate(value) and not _DATE_SHAPED.match(value)


def normalise_apk_introduced(value, counters=None):
    """An Alpine `introduced` as apk can compare it (rule 1a): "0" and valid apk versions unchanged, an upstream
    `X.Y.Z-N` dotted, anything else "0". `counters` counts the two kinds of change."""
    if value == "0" or _apk_ok(value):
        return value
    if not _DATE_SHAPED.match(value) and _UPSTREAM_DASHED.match(value):
        dotted = value.replace("-", ".")
        if _apk_ok(dotted):
            if counters is not None:
                counters[INTRO_NORMALISED] += 1
            return dotted
    if counters is not None:
        counters[INTRO_ZEROED] += 1
    return "0"


def apk_range_pairs(affected, counters):
    """[(introduced, fixed)] for one Alpine affected[] entry (rule 1 of the Alpine notes above). Dropped fixed
    events are counted in `counters`: `redundant fixed` (a later fixed of an already closed range) and `empty
    range (fixed below introduced)` (a fixed before any introduced, such as prosody [13.0.0, 0.12.6-r0)).
    Raises ShapeError on any other shape."""
    ranges = affected.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise ShapeError("no ranges")
    pairs = []
    for rng in ranges:
        events = _event_list(rng)
        counters["shape [" + ", ".join("introduced 0" if (k, v) == ("introduced", "0") else
                                       "introduced X" if k == "introduced" else k for k, v in events) + "]"] += 1
        if any(k == "fixed" and v in NOT_AFFECTED_FIXED for k, v in events):
            counters[NOT_AFFECTED] += 1
            continue
        events = [(k, normalise_apk_introduced(v, counters) if k == "introduced" else v) for k, v in events]
        # A fixed value apk cannot order (opensmtpd 6.6.2p1-r0) is kept out of the walk, so one bad event never
        # unsorts the range or costs it a good fix; it becomes a pair of its own (with the introduced it followed
        # in the given order) for resolve_apk() to reject and count toward REJECT_LIMIT.
        bad, last_intro = [], "0"
        for kind, value in events:
            if kind == "introduced":
                last_intro = value
            elif not _apk_ok(value):
                bad.append((last_intro, value))
        if bad:
            counters[BAD_FIXED] += len(bad)
            events = [(k, v) for k, v in events if k == "introduced" or _apk_ok(v)]
        events = sorted(events, key=_apk_event_key)
        introduced, closed_any = None, False
        for kind, value in events:
            if kind == "introduced":
                if introduced is not None:
                    if not bad:
                        raise ShapeError("introduced twice without a fixed between")
                    # The fixed between them was a bad value kept apart: the range stays open from the lower.
                    counters["introduced while open (its fixed was bad)"] += 1
                    continue
                introduced = value
            elif introduced is None:
                counters["redundant fixed" if closed_any else "empty range (fixed below introduced)"] += 1
            else:
                pairs.append((introduced, value))
                introduced, closed_any = None, True
        pairs.extend(bad)
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
    __slots__ = ("ids", "advisory", "advisory_ids", "pkg_priority", "adv_date", "rec_date", "modified", "tokens")

    def __init__(self):
        self.ids = set()
        self.advisory = False
        self.advisory_ids = set()   # the ids a USN/DSA/DLA naming this fix lists (plan 3.2: "a DSA/DLA exists")
        self.pkg_priority = {}      # id -> affected[].ecosystem_specific.ubuntu_priority (beats the record's)
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
            if not upstream and rid.startswith("ALPINE-") and _CVE.match(rid[len("ALPINE-"):]):
                upstream = [rid[len("ALPINE-"):]]   # Alpine ids are upstream CVEs: never ship ALPINE-CVE-*
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
                    dropped = collections.Counter()
                    if release.format == "apk":
                        pairs = apk_range_pairs(affected, dropped)
                        for reason, count in dropped.items():
                            stats[f"{release.key}: {reason}"] += count
                    else:
                        pairs = range_pairs(affected)
                    if not name_ok(source, release.format):
                        raise ShapeError(f"source name {source!r}")
                except ShapeError as error:
                    stats[f"{release.key}: unknown range shape"] += 1
                    if len(shapes) < 10:
                        shapes.append(f"{rid} {release.ecosystem} {source}: {error}")
                    continue
                if not pairs:
                    if not (release.format == "apk" and dropped[NOT_AFFECTED]):
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
                specific = affected.get("ecosystem_specific") or {}
                pkg_priority = _UBUNTU_PRIORITY.get(str(specific.get("ubuntu_priority", "")).lower())
                tokens = {t for t in (leading_token(v) for v in affected.get("versions") or []
                                      if isinstance(v, str)) if t}
                for introduced, fixed in pairs:
                    stats[f"{release.key}: fixed rows"] += 1
                    cand = candidates[release.key].get((source, introduced, fixed))
                    if cand is None:
                        cand = candidates[release.key][(source, introduced, fixed)] = Candidate()
                    cand.ids.update(ids)
                    cand.tokens |= tokens
                    if pkg_priority is not None and release.family == "ubuntu":
                        for cve in ids:
                            cand.pkg_priority[cve] = max(pkg_priority, cand.pkg_priority.get(cve, -1))
                    if is_adv:
                        cand.advisory = True
                        cand.advisory_ids.update(ids)
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


def parse_sources(handle, skipped=None):
    """{source: highest version text} from a Sources stream (deb822). Extra-Source-Only stanzas (old sources
    kept only for Built-Using) are skipped. A version our strict parser refuses (dpkg tolerates a few, with a
    warning) is skipped and counted in `skipped` (a Counter), never fatal."""
    out = {}
    package = version = None
    extra = False

    def flush():
        if package and version and not extra:
            if _cmp_ok(version) is None:
                if skipped is not None:
                    skipped["archive versions skipped (unparseable)"] += 1
                return
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


def verify_inrelease(data, keyring):
    """The signed body of an InRelease file, after gpgv finds at least one VALIDSIG from `keyring` and no
    BADSIG. A signature by a key the keyring lacks (an older release key) is tolerated, as apt does."""
    gpgv = shutil.which("gpgv")
    if gpgv is None:
        raise FeedError("gpgv is not installed: cannot verify InRelease signatures")
    with tempfile.TemporaryDirectory(prefix="vulnfeed-gpgv-") as home:
        signed, plain = os.path.join(home, "InRelease"), os.path.join(home, "Release")
        with open(signed, "wb") as handle:
            handle.write(data)
        result = subprocess.run([gpgv, "--homedir", home, "--status-fd", "1", "--keyring",
                                 os.path.abspath(keyring), "--output", plain, signed],
                                capture_output=True, timeout=120)
        status = result.stdout.decode("utf-8", "replace").splitlines()
        if any(line.startswith("[GNUPG:] BADSIG ") for line in status):
            raise FeedError("InRelease has a BAD signature")
        if not any(line.startswith("[GNUPG:] VALIDSIG ") for line in status) or not os.path.isfile(plain):
            raise FeedError("InRelease has no valid signature from the pinned keyring")
        with open(plain, "rb") as handle:
            return handle.read()


def release_field(body, name):
    match = re.search(rf"^{name}: *(.+)$", body.decode("utf-8", "replace"), re.M)
    return match.group(1).strip() if match else None


def check_freshness(suite, body, date, now, previous_date):
    """Replay defence for a verified InRelease: an expired `Valid-Until` (Debian -security and -updates carry
    one) fails, and so does a `Date` older than the one a previous build recorded for this suite (Ubuntu's
    pockets carry no Valid-Until, so this is their only defence). `now` None skips the Valid-Until check
    (snapshot files, which are long expired by design)."""
    valid_until = release_field(body, "Valid-Until")
    if now is not None and valid_until is not None and _release_date(valid_until) < now:
        raise FeedError(f"{suite}: InRelease expired (Valid-Until {_release_date(valid_until)}, now {now})")
    if previous_date is not None and date < previous_date:
        raise FeedError(f"{suite}: InRelease Date {date} is older than the {previous_date} a previous build "
                        "recorded (a replayed old file?)")


def load_suite(cache, mirror, suite, used, log, offline=False, family=None, skipped=None, now=None,
               previous_date=None):
    """({source: version}, Release date) for every component of one suite. The suite's InRelease is verified
    against ARCHIVE_KEYRINGS[family], and for freshness (check_freshness), before any of its digests is used."""
    release_url = f"{mirror}/dists/{suite}/InRelease"
    release_cache = os.path.join(cache, "archive", "release", re.sub(r"[^a-z0-9.-]", "_", mirror) + "_" + suite)
    if offline:
        with open(release_cache, "rb") as handle:
            data = handle.read()
    else:
        data = netfetch.get_bytes(release_url, netfetch.RELEASE_CAP)
        os.makedirs(os.path.dirname(release_cache), exist_ok=True)
        with open(release_cache, "wb") as handle:
            handle.write(data)
    try:
        body = verify_inrelease(data, ARCHIVE_KEYRINGS[family])
    except FeedError as error:
        raise FeedError(f"{release_url}: {error}") from None
    date, files = parse_release(body)
    check_freshness(suite, body, date, now, previous_date)
    if not files:
        raise FeedError(f"{release_url} lists no Sources.xz")
    versions = {}
    fetched = 0
    for path, (algo, digest, size) in sorted(files.items()):
        local, new = netfetch.fetch_by_hash(cache, f"{mirror}/dists/{suite}/{path}", algo, digest, size, used,
                                            offline)
        fetched += new
        with lzma.open(local, "rt", encoding="utf-8", errors="replace") as handle:
            merge_max(versions, parse_sources(handle, skipped))
    log.info(f"archive {suite}: InRelease signature OK, {len(files)} component(s), {len(versions)} sources, "
             f"Release {date}{f', {fetched} downloaded' if fetched else ', all cached'}")
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
    data = verify_inrelease(netfetch.get_bytes(f"{base}/dists/{release.codename}/InRelease",
                                               netfetch.RELEASE_CAP), ARCHIVE_KEYRINGS[release.family])
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
        kept, rules, best = {}, {}, -1
        for cve in cand.ids:
            band, rule = severity(release, cve, cand, info)
            decisions[rule] += 1
            best = max(best, band)
            if band >= HIGH:
                kept[cve] = band
                rules[cve] = rule
        if not kept:
            drop("below High (dropped)")
            dropped[-1].append(best)
            continue
        counters["shipped"] += 1
        date, date_source = (cand.adv_date, "advisory") if cand.adv_date else (cand.rec_date, "record")
        rows.append({"source": source, "introduced": introduced, "fixed": fixed,
                     "severity": max(kept.values()), "ids": sorted(kept), "kernel": is_kernel(source),
                     "date": date, "dateSource": date_source, "modified": cand.modified,
                     "rules": dict(sorted(rules.items()))})
    return rows, examples, dropped


def resolve_apk(release, cands, info, counters, decisions):
    """Rules for one Alpine release (the Alpine notes at the top): reject bad versions, severity, kernel fold.
    Same return shape as resolve()."""
    rows, examples, dropped = [], [], []
    for (source, introduced, fixed), cand in sorted(cands.items()):
        reason = None
        if _DATE_SHAPED.match(fixed) or (introduced != "0" and _DATE_SHAPED.match(introduced)):
            reason = "date-shaped"
        elif not apkver.validate(fixed):
            reason = "fixed not an apk version"
        elif introduced != "0" and not apkver.validate(introduced):
            reason = "introduced not an apk version"
        if reason:
            counters["rejected"] += 1
            counters[f"rejected: {reason}"] += 1
            dropped.append([source, introduced, fixed, f"rejected: {reason}"])
            if len(examples) < 8:
                examples.append(f"{source} [{introduced!r}, {fixed!r}] ({reason}; "
                                f"{', '.join(sorted(cand.ids))[:60]})")
            continue
        kept, rules, best = {}, {}, -1
        for cve in cand.ids:
            band, rule = severity(release, cve, cand, info)
            decisions[rule] += 1
            best = max(best, band)
            if band >= HIGH:
                kept[cve] = band
                rules[cve] = rule
        if not kept:
            counters["below High (dropped)"] += 1
            dropped.append([source, introduced, fixed, "below High (dropped)", best])
            continue
        counters["shipped"] += 1
        kernel = is_kernel(source, "apk")
        if kernel:
            counters["kernel rows"] += 1
        # `date` is the CVE's record date, kept in the intermediates only; the file carries no package date and
        # a null kernel date (no fix date in OSV Alpine).
        rows.append({"source": source, "introduced": introduced, "fixed": fixed,
                     "severity": max(kept.values()), "ids": sorted(kept), "kernel": kernel,
                     "date": cand.rec_date, "dateSource": "record (CVE, not the fix)", "modified": cand.modified,
                     "rules": dict(sorted(rules.items()))})
    return rows, examples, dropped


def severity(release, cve, cand, info):
    """(band, rule) for one id of one row, by the release family's chain (plan 3.2)."""
    ubuntu, score = info.get(cve, (None, None))
    if release.family == "ubuntu":
        if cve in cand.pkg_priority:
            return cand.pkg_priority[cve], "ubuntu package priority"
        if ubuntu is not None:
            return ubuntu, "ubuntu priority"
        if score is not None:
            return cvss.band(score), "cvss"
        return cvss.MEDIUM, "default medium"
    if score is not None:
        return cvss.band(score), "cvss"
    if release.family == "alpine":
        return cvss.MEDIUM, "default medium"
    if cve in cand.advisory_ids:
        return HIGH, "dsa/dla exists -> high"
    return cvss.MEDIUM, "default medium"


def release_body(release, rows):
    """The shipped JSON object (plan 4.1)."""
    apk = release.format == "apk"
    pkgs, kernel = collections.defaultdict(list), collections.defaultdict(list)
    for row in rows:
        if row["kernel"]:
            kernel[row["source"]].append([row["introduced"], row["fixed"], row["severity"], len(row["ids"]),
                                          None if apk else row["date"]])
        else:
            pkgs[row["source"]].append([row["introduced"], row["fixed"], row["severity"], row["ids"]])
    fmt = release.format
    return {"release": release.key, "format": fmt, "keyedBy": "origin" if apk else "source",
            "pkgs": {k: sort_rows(v, fmt) for k, v in sorted(pkgs.items())},
            "kernel": {k: sort_rows(v, fmt) for k, v in sorted(kernel.items())}}


def version_cmp(fmt):
    """The comparison (a, b) -> -1/0/1 of a release format."""
    if fmt == "apk":
        return apkver.compare
    return lambda a, b: DpkgVersion.parse(a)._cmp(DpkgVersion.parse(b))


def version_ok(fmt, text):
    """A valid version of the format, not date-shaped (what check_release_body and the rules accept)."""
    if not isinstance(text, str) or _DATE_SHAPED.match(text):
        return False
    return apkver.validate(text) if fmt == "apk" else _cmp_ok(text) is not None


def _version_or_zero_cmp(a, b, fmt="dpkg"):
    """Compares two `introduced` values: "0" is below every version."""
    if a == b:
        return 0
    if a == "0":
        return -1
    if b == "0":
        return 1
    return version_cmp(fmt)(a, b)


def sort_rows(rows, fmt="dpkg"):
    """Rows ordered by fixed version, then introduced (then the text, so equal apk versions sort stably)."""
    cmp = version_cmp(fmt)
    return sorted(rows, key=functools.cmp_to_key(
        lambda a, b: cmp(a[1], b[1]) or _version_or_zero_cmp(a[0], b[0], fmt)
        or (a[1] > b[1]) - (a[1] < b[1]) or (a[0] > b[0]) - (a[0] < b[0])))


_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|(USN|DSA|DLA|DTSA|LSN)-\d+(-\d+)?|(UBUNTU|DEBIAN)-CVE-\d{4}-\d{4,})$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Per format: (keyedBy, id pattern). apk ids are upstream CVEs only.
_BODY_FORMATS = {"dpkg": ("source", _ID), "apk": ("origin", _CVE)}
FORMAT_OF = {r.key: r.format for r in RELEASES}


def check_release_body(body, key, entry):
    """Raises FeedError unless a release file has the plan 4.1 shape and matches its manifest entry."""
    def fail(why):
        raise FeedError(f"{entry['file']}: {why}")
    if not isinstance(body, dict) or set(body) != {"release", "format", "keyedBy", "pkgs", "kernel"}:
        fail("keys must be release, format, keyedBy, pkgs, kernel")
    fmt = entry["format"]
    if body["release"] != key or body["format"] != fmt or fmt not in _BODY_FORMATS \
            or FORMAT_OF.get(key, fmt) != fmt or body["keyedBy"] != _BODY_FORMATS[fmt][0]:
        fail("release/format/keyedBy do not match the manifest")
    id_re = _BODY_FORMATS[fmt][1]
    count = 0
    for section, width in (("pkgs", 4), ("kernel", 5)):
        if not isinstance(body[section], dict):
            fail(f"{section} is not an object")
        for source, rows in body[section].items():
            if not name_ok(source, fmt) or (section == "kernel") != is_kernel(source, fmt):
                fail(f"bad {section} source {source!r}")
            if not isinstance(rows, list) or not rows:
                fail(f"{source}: no rows")
            for row in rows:
                count += 1
                if not isinstance(row, list) or len(row) != width:
                    fail(f"{source}: row {row!r} is not {width} fields")
                introduced, fixed, sev = row[0], row[1], row[2]
                intro_ok = introduced == "0" or (version_ok(fmt, introduced) if fmt == "apk"
                                                 else _cmp_ok(introduced) is not None)
                if not intro_ok or not version_ok(fmt, fixed):
                    fail(f"{source}: bad version in {row!r}")
                if type(sev) is not int or sev not in (cvss.HIGH, cvss.CRITICAL):
                    fail(f"{source}: severity {sev!r} is not High or Critical")
                if section == "pkgs":
                    ids = row[3]
                    if not isinstance(ids, list) or not ids or ids != sorted(set(ids)) \
                            or not all(isinstance(i, str) and id_re.match(i) for i in ids):
                        fail(f"{source}: bad ids {ids!r}")
                else:
                    # apk kernel rows always carry a null date (no fix date in OSV Alpine).
                    if type(row[3]) is not int or row[3] < 1 or not (row[4] is None or (
                            fmt == "dpkg" and isinstance(row[4], str) and _DAY.match(row[4]))):
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


def read_apk_inventory(path):
    """{origin: highest version} from the app's Pro probe listing of /lib/apk/db/installed (`grep -E
    "^([PVo]:|$)"`: the P: name, V: version and o: origin lines and the blank record separators, in file
    order). A record's origin is its `o:`, else its name; per origin the HIGHEST version (by apkver) of its
    packages counts (plan 3.3). `#` lines are comments."""
    out = {}
    record = {}

    def flush():
        if not record:
            return
        name, version = record.get("P"), record.get("V")
        if not name or not version:
            raise FeedError(f"{os.path.basename(path)}: a record without P: or V: ({record!r:.80})")
        origin = record.get("o") or name
        old = out.get(origin)
        if old is None or apkver.compare(version, old) > 0:
            out[origin] = version
        record.clear()

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#"):
                continue
            if not line:
                flush()
                continue
            if len(line) < 2 or line[1] != ":" or line[0] not in "PVo":
                raise FeedError(f"{os.path.basename(path)}: bad line {line[:60]!r}")
            if line[0] in record:
                raise FeedError(f"{os.path.basename(path)}: {line[0]}: twice in one record")
            record[line[0]] = line[2:]
    flush()
    return out


def read_case_inventory(path, fmt):
    return read_apk_inventory(path) if fmt == "apk" else read_inventory(path)


def apk_hits(body, inventory):
    """{origin: [fixed, ...]} for the package rows of an apk release FILE that the inventory is in: a row
    matches when introduced <= installed < fixed (introduced "0" always holds). Kernel rows are not counted.
    This is exactly the app's matcher, on the shipped file (Alpine rows carry no fix date to filter on)."""
    hits = collections.defaultdict(list)
    for origin, rows in body["pkgs"].items():
        installed = inventory.get(origin)
        if installed is None:
            continue
        for introduced, fixed, _, _ in rows:
            if introduced != "0" and apkver.compare(installed, introduced) < 0:
                continue
            if apkver.compare(installed, fixed) < 0:
                hits[origin].append(fixed)
    return dict(hits)


def published_before(row, capture):
    """True when this row's fix date (the earliest advisory naming it, else the earliest record) is before the
    capture date."""
    return bool(row["date"]) and row["date"] < capture


def golden_hits(rows, inventory, capture, at_capture=None):
    """({source: [fixed, ...]}, [unarchived]) for non-kernel rows published before `capture` that the inventory
    is below. With `at_capture` ({source: highest archive version at the capture time}) a row also needs its fix
    to have been in the archive then, which keeps a frozen fixture from drifting when OSV later records an old
    CVE's fix; a would-be hit on a source the frozen archive does not list at all is returned in `unarchived`
    (the fixture and its archive file disagree, which is an error)."""
    hits = collections.defaultdict(list)
    unarchived = []
    for row in rows:
        if row["kernel"] or not published_before(row, capture):
            continue
        installed = inventory.get(row["source"])
        if installed is None:
            continue
        fixed = DpkgVersion.parse(row["fixed"])
        have = DpkgVersion.parse(installed)
        if row["introduced"] != "0" and have < DpkgVersion.parse(row["introduced"]):
            continue
        if not have < fixed:
            continue
        if at_capture is not None:
            then = at_capture.get(row["source"])
            if then is None:
                unarchived.append(f"{row['source']} {row['fixed']}")
                continue
            if DpkgVersion.parse(then) < fixed:
                continue
        hits[row["source"]].append(row["fixed"])
    return dict(hits), unarchived


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
        versions, date = load_suite(cache, mirror, suite, set(), log, family=release.family)
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


def golden_cases(golden_dir=GOLDEN_DIR):
    with open(os.path.join(golden_dir, "expected.json"), encoding="utf-8") as handle:
        return json.load(handle)["cases"]


EXTRA_HIT_LIMIT = 3     # unexpected golden sources: up to 2 warn, 3 or more fail
# Severity rules that are not a published score: an unexpected golden hit rated High by one of these fails, since
# it says more about our chain than about the data.
HEURISTIC_RULES = ("ubuntu package priority", "dsa/dla exists -> high")


def check_golden(key, rows, log, golden_dir=GOLDEN_DIR):
    """The golden cases of one release. Returns the failures (an empty list when they pass).

    Errors: an expected source not flagged (a regression that drops a real fix), and a would-be hit on a
    source the frozen archive file does not list. A flagged source the case does not expect is a WARNING:
    every row counted is already pinned to the archive at capture, so an extra hit can only come from OSV
    re-rating an old CVE (Medium to High) or adding ids, which is data, not a builder regression. Except: 3 or
    more unexpected sources, or any unexpected hit whose High came from a HEURISTIC_RULES rule (per-id
    provenance is in each row's `rules`), fail."""
    failures = []
    fmt = FORMAT_OF.get(key, "dpkg")
    for case in golden_cases(golden_dir):
        if case["release"] != key:
            continue
        inventory = read_case_inventory(os.path.join(golden_dir, case["fixture"]), fmt)
        if fmt == "apk":
            # No fix dates and no archive at capture: the shipped rows, matched as the app does.
            hits, unarchived = apk_hits(release_body(Release(key, "alpine", None, None), rows), inventory), []
        else:
            at_capture = read_inventory(os.path.join(golden_dir, case["archive"])) if case.get("archive") else None
            hits, unarchived = golden_hits(rows, inventory, case["capture"], at_capture)
        got = set(hits)
        expected = set(case.get("exact", case.get("atLeast", [])))
        key_of = apkver.sort_key if fmt == "apk" else sort_key
        detail = ", ".join(f"{s} {inventory[s]} < {max(hits[s], key=key_of)}" for s in sorted(got)) or "none"
        if expected - got:
            failures.append(f"golden {case['fixture']}: missing {sorted(expected - got)} [{detail}]")
        if unarchived:
            failures.append(f"golden {case['fixture']}: hits on sources not in {case['archive']}: "
                            + ", ".join(unarchived[:5]))
        # apk `atLeast` cases are limited too (M1): with no fix dates a frozen image gains real hits, but 3 or more
        # unexpected origins at once is a matcher or data problem, not drift.
        extra = sorted(got - expected) if ("exact" in case or fmt == "apk") else []
        if extra:
            weak = sorted({f"{row['source']} ({rule})" for row in rows if row["source"] in extra
                           and row["fixed"] in hits[row["source"]]
                           for rule in (row.get("rules") or {}).values() if rule in HEURISTIC_RULES})
            if len(extra) >= EXTRA_HIT_LIMIT:
                failures.append(f"golden {case['fixture']}: {len(extra)} unexpected sources flagged {extra} "
                                f"(the limit for a warning is {EXTRA_HIT_LIMIT - 1})")
            elif weak:
                failures.append(f"golden {case['fixture']}: unexpected hit(s) rated High by a heuristic rule, "
                                f"not a score: {', '.join(weak)}")
            else:
                why = ("a new secdb fix for a frozen image" if fmt == "apk" else
                       "OSV re-rated or added a fix that was in the archive at capture")
                log.warn(f"golden {case['fixture']}: also flags {extra} (not expected; {why}; update "
                         "expected.json if it is right)")
        if not failures:
            when = "every shipped row, no fix dates" if fmt == "apk" else f"before {case['capture']}"
            log.info(f"golden {case['fixture']} ({key}, {when}): {len(got)} source(s) flagged: {detail}")
    return failures


# --- row-count gates -----------------------------------------------------------------------------------
GATES_DIR = os.path.join(HERE, "..", "gates")
MIN_SHARE_OF_PREVIOUS = 0.5     # a release may never fall below half its previous row count


class ConfigError(FeedError):
    """A broken committed configuration (gates, baselines, RELEASES/RETIRED). Fails the WHOLE build: it comes
    from a commit, not from upstream, and fail-soft must not hide it."""


def load_gates(gates_dir=GATES_DIR, releases=RELEASES):
    """(minimums {release: rows}, overrides [{release, min, max, expires, reason}]) from gates/."""
    try:
        with open(os.path.join(gates_dir, "minimums.json"), encoding="utf-8") as handle:
            minimums = json.load(handle)["minimums"]
        with open(os.path.join(gates_dir, "overrides.json"), encoding="utf-8") as handle:
            overrides = json.load(handle)["rowCount"]
    except (OSError, ValueError, KeyError) as error:
        raise ConfigError(f"gates/: {error}") from None
    keys = {r.key for r in releases}
    if not isinstance(minimums, dict) or set(minimums) != keys \
            or not all(type(v) is int and v >= 1 for v in minimums.values()):
        raise ConfigError("gates/minimums.json must give every release in RELEASES a minimum of at least 1 row")
    if not isinstance(overrides, list):
        raise ConfigError("gates/overrides.json rowCount must be a list")
    for item in overrides:
        if not isinstance(item, dict) or set(item) != {"release", "min", "max", "expires", "reason"} \
                or item["release"] not in keys or type(item["min"]) is not int or type(item["max"]) is not int \
                or not 0 <= item["min"] <= item["max"] or not isinstance(item["expires"], str) \
                or not _DAY.match(item["expires"]) or not isinstance(item["reason"], str) or not item["reason"]:
            raise ConfigError(f"gates/overrides.json: bad override {item!r}")
    return minimums, overrides


def row_gate(key, rows, previous_rows, minimum, overrides, today, log):
    """None when `rows` passes for release `key`, else the reason. An unexpired override (expires >= today)
    replaces every other row rule with its [min, max]; expired ones are ignored and logged."""
    for item in overrides:
        if item["release"] != key:
            continue
        if item["expires"] < today:
            log.info(f"row-count gate: {key}: override until {item['expires']} has expired, ignored")
            continue
        if item["min"] <= rows <= item["max"]:
            log.info(f"row-count gate: {key}: {rows} rows within the override [{item['min']}, {item['max']}] "
                     f"until {item['expires']} ({item['reason']})")
            return None
        return f"{rows} rows, outside the override [{item['min']}, {item['max']}]"
    floor = minimum
    if previous_rows is not None:
        floor = max(floor, int(previous_rows * MIN_SHARE_OF_PREVIOUS + 0.999))
    if rows < floor:
        return f"{rows} rows, under the floor {floor} (committed minimum {minimum}, previous {previous_rows})"
    if previous_rows is None:
        log.info(f"row-count gate: {key}: no previous count ({rows} rows, committed minimum {minimum}), allowed")
        return None
    allowed = max(previous_rows * ROW_SWING, ROW_SWING_FLOOR)
    if abs(rows - previous_rows) > allowed:
        return f"{previous_rows} -> {rows} rows (allowed +-{allowed:.0f})"
    return None


# A release dropped from RELEASES must be listed here (and in the sign job's `retired` set), or the build
# fails: that is how a removal is told apart from a release that vanished by mistake. Its files stay on Pages
# only as carry-overs of the last builds that named them, then age out.
RETIRED_RELEASES = ()


def check_gone(previous, releases=RELEASES, retired=RETIRED_RELEASES):
    keys = {r.key for r in releases}
    if keys & set(retired):
        raise ConfigError(f"release(s) both in RELEASES and RETIRED_RELEASES: {sorted(keys & set(retired))}")
    gone = sorted(set(previous or {}) - keys - set(retired))
    if gone:
        raise ConfigError(f"release(s) in the previous build but neither in RELEASES nor RETIRED_RELEASES: {gone}")


# --- the stage -----------------------------------------------------------------------------------------
# Upstream-shaped failures (network, signature, digest, archive or OSV data): the release goes stale. Anything
# else is a builder bug: still carried forward (curated keeps publishing), but recorded as `bug` with its
# traceback, and the workflow ends red.
UPSTREAM_ERRORS = (FeedError, OSError, EOFError, lzma.LZMAError, zipfile.BadZipFile, json.JSONDecodeError,
                   UnicodeDecodeError, VersionError, ShapeError, subprocess.SubprocessError)
BUG_PREFIX = "bug: "
_SOFT = (Exception,)


def soft_reason(context, error):
    """The failure text for one fail-soft catch: upstream-shaped errors as `context: error`, anything else as
    BUG_PREFIX + the traceback."""
    if isinstance(error, UPSTREAM_ERRORS):
        return f"{context}: {error}"
    import traceback
    trace = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    return f"{BUG_PREFIX}{context}: {type(error).__name__}: {error}\n{trace[-3500:]}"


def build_releases(site_v1, log, cache, work, previous=None, offline=False, releases=RELEASES,
                   golden_dir=GOLDEN_DIR, gates_dir=GATES_DIR, today=None, retired=RETIRED_RELEASES,
                   now=None, previous_dates=None):
    """Writes v1/r/<release>-<sha16>.json for every release that passes; returns (releases, sources, failures).

    FAIL-SOFT per release: a fetch, ingest or gate failure of one release (or of everything its archive or OSV
    zip feeds) lands in `failures` {release: reason}, and build.py carries that release's last published
    entry forward. Only ConfigError (a broken committed configuration) raises. `previous` is the previous
    build's manifest `releases` (None for the first build). Intermediates (every shipped row with its
    publish date, every dropped row with its reason) go to `work`/<release>.rows.json. `now` (UTC ISO) enforces
    InRelease Valid-Until; `previous_dates` {suite: Date} from the previous build's record makes each suite's
    Date monotonic."""
    started = time.time()
    today = today or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    os.makedirs(os.path.join(site_v1, "r"), exist_ok=True)
    os.makedirs(work, exist_ok=True)
    check_gone(previous, releases, retired)
    minimums, overrides = load_gates(gates_dir, releases)
    sources = {"osv": {}, "archive": {}, "baseline": {}}
    failures = {}
    used = set()

    def fail(keys, reason):
        for key in keys:
            if key not in failures:
                failures[key] = reason
                log.warn(f"{key}: not rebuilt, the previous file is carried forward: {reason.splitlines()[0]}")

    def dependents(base):
        return [r.key for r in releases if r.base_key == base]

    archives, baselines = {}, {}
    for release in releases:
        if release.esm or release.key in archives or not release.has_archive:
            continue
        baseline_file = None
        if release.family == "debian":
            baseline_file, day = load_baseline_file(release)
            if baseline_file is None:
                raise ConfigError(f"{release.key}: builder/baselines/{release.key}.tsv is missing "
                                  "(run `builder/build.py baseline`)")
        try:
            merged, release_pocket, dates, skipped = {}, None, {}, collections.Counter()
            for mirror, suite in release.suites():
                versions, date = load_suite(cache, mirror, suite, used, log, offline, release.family, skipped,
                                            now, (previous_dates or {}).get(suite))
                dates[suite] = date
                merge_max(merged, versions)
                if suite == release.codename:
                    release_pocket = (versions, date)
            if skipped:
                log.info(f"archive {release.key}: " + ", ".join(f"{k} {v}" for k, v in skipped.items()))
        except _SOFT as error:
            fail(dependents(release.key), soft_reason("archive", error))
            continue
        sources["archive"].update(dates)
        archives[release.key] = merged
        if release.family == "ubuntu":
            baselines[release.key] = release_pocket[0]
            sources["baseline"][release.key] = release_pocket[1][:10]
        else:
            baselines[release.key] = baseline_file
            sources["baseline"][release.key] = day
    if not offline and not failures:
        netfetch.prune_by_hash(cache, used, log)

    out = {}
    for zip_name in sorted({r.osv_zip for r in releases}):
        members = [r for r in releases if r.osv_zip == zip_name and r.key not in failures]
        if not members:
            continue
        try:
            zip_path = netfetch.fetch_osv_zip(cache, zip_name, log, offline)
            candidates, info, stats, shapes, newest = ingest(zip_path, members, log)
        except _SOFT as error:
            fail([r.key for r in members], soft_reason(f"osv {zip_name}", error))
            continue
        if newest:
            netfetch.record_highwater(cache, zip_name, newest)
            sources["osv"][zip_name] = netfetch.ts_seconds(newest)
        for key, value in sorted(stats.items()):
            if ":" not in key:
                log.info(f"osv {zip_name}: {key} {value}")
        if shapes:
            log.info(f"osv {zip_name}: unknown shapes, e.g. " + "; ".join(shapes[:5]))
        zip_fixed = zip_rejected = zip_intro = zip_events = 0
        pending = {}
        for release in members:
            try:
                pending[release.key] = _one_release(release, candidates[release.key], info, stats, archives,
                                                    baselines, work, log)
                zip_fixed += len(candidates[release.key])
                zip_rejected += pending[release.key]["rejected"]
                zip_intro += pending[release.key]["intro_zeroed"]
                zip_events += pending[release.key]["fixed_events"]
            except _SOFT as error:
                fail([release.key], soft_reason("build", error))
        share = zip_rejected / zip_fixed if zip_fixed else 0.0
        intro_share = zip_intro / zip_events if zip_events else 0.0
        log.info(f"osv {zip_name}: rejected {zip_rejected} of {zip_fixed} fixed rows ({share:.3%})"
                 + (f"; {zip_intro} of {zip_events} fixed range events had an unparseable introduced read as "
                    f"\"0\" ({intro_share:.3%})" if zip_intro else ""))
        if share >= REJECT_LIMIT:
            fail(list(pending), f"osv {zip_name}: {share:.2%} of fixed versions rejected, the limit is "
                                f"{REJECT_LIMIT:.1%}")
            continue
        if intro_share >= INTRODUCED_REJECT_LIMIT:
            fail(list(pending), f"osv {zip_name}: {intro_share:.2%} of range events had an unparseable "
                                f"introduced (read as \"0\"), the limit is {INTRODUCED_REJECT_LIMIT:.1%}")
            continue
        for key, built in sorted(pending.items()):
            problems = []
            if built["unknown"]:
                problems.append(f"{built['unknown']} unknown range shape(s) (fail closed)")
            if len(built["data"]) > FILE_CAP:
                problems.append(f"{len(built['data'])} bytes, over the {FILE_CAP}-byte cap")
            entry = {"format": built["format"], "file": "r/" + content_name(key, built["data"]),
                     "sha256": sha256_hex(built["data"]), "bytes": len(built["data"]), "rows": built["count"]}
            try:
                check_release_body(json.loads(built["data"]), key, entry)
            except FeedError as error:
                problems.append(f"schema: {error}")
            problems += check_golden(key, built["rows"], log, golden_dir)
            reason = row_gate(key, built["count"], ((previous or {}).get(key) or {}).get("rows"),
                              minimums[key], overrides, today, log)
            if reason:
                problems.append(f"row-count gate: {reason}")
            if problems:
                fail([key], "; ".join(problems))
                continue
            with open(os.path.join(site_v1, entry["file"]), "wb") as handle:
                handle.write(built["data"])
            out[key] = entry
    log.info(f"releases: {len(out)} built, {len(failures)} carried forward, in {time.time() - started:.0f} s")
    return out, sources, failures


def _one_release(release, cands, info, stats, archives, baselines, work, log):
    counters, decisions = collections.Counter(), collections.Counter()
    base = release.base_key
    if release.has_archive:
        rows, examples, dropped = resolve(release, cands, info, archives[base], baselines[base], counters,
                                          decisions)
    else:
        rows, examples, dropped = resolve_apk(release, cands, info, counters, decisions)
    body = release_body(release, rows)
    data = body_bytes(body)
    summary = {k.split(": ", 1)[1]: v for k, v in stats.items() if k.startswith(release.key + ": ")}
    log.info(f"{release.key}: {len(cands)} distinct fixed rows; "
             + ", ".join(f"{k} {v}" for k, v in sorted(counters.items()) if not k.startswith("rejected:"))
             + f"; {row_count(body)} rows, {len(data)} bytes")
    log.info(f"{release.key}: severity decisions (per id): "
             + (", ".join(f"{k} {v}" for k, v in sorted(decisions.items())) or "none"))
    log.info(f"{release.key}: osv entries: " + ", ".join(f"{k} {v}" for k, v in sorted(summary.items())))
    if counters["rejected"]:
        log.info(f"{release.key}: rejected {counters['rejected']} ("
                 + ", ".join(f"{k[10:]} {v}" for k, v in sorted(counters.items()) if k.startswith("rejected: "))
                 + "), e.g. " + "; ".join(examples[:4]))
    if release.format == "apk":
        # Per release (the INTRODUCED_REJECT_LIMIT gate is zip-wide, as REJECT_LIMIT is): one release's share.
        events = stats[f"{release.key}: fixed rows"]
        zeroed = stats[f"{release.key}: {INTRO_ZEROED}"]
        log.info(f"{release.key}: introduced: {stats[f'{release.key}: {INTRO_NORMALISED}']} normalised to the "
                 f"dotted form, {zeroed} unparseable read as \"0\" ({zeroed / events if events else 0:.3%} of its "
                 f"{events} fixed range events); {stats[f'{release.key}: {NOT_AFFECTED}']} not-affected range(s) "
                 f"dropped; {stats[f'{release.key}: {BAD_FIXED}']} bad fixed event(s) kept apart")
    kernels = sorted({r["source"] for r in rows if r["kernel"]})
    if kernels:
        log.info(f"{release.key}: kernel sources folded ({len(kernels)}): {' '.join(kernels)}")
    with open(os.path.join(work, f"{release.key}.rows.json"), "w", encoding="utf-8") as handle:
        json.dump({"release": release.key, "counters": counters, "decisions": decisions,
                   "osv": summary, "rows": rows, "dropped": dropped}, handle, indent=0, sort_keys=True)
    return {"rows": rows, "data": data, "count": row_count(body), "rejected": counters["rejected"],
            "format": release.format, "intro_zeroed": stats[f"{release.key}: {INTRO_ZEROED}"],
            "fixed_events": stats[f"{release.key}: fixed rows"],
            "unknown": stats[f"{release.key}: unknown range shape"]}
