"""The S2 rules (plan section 3) on small, hand-made OSV records and a fake archive, then one end-to-end
build_releases() over file:// mirrors."""
import collections
import io
import json
import lzma
import os
import shutil
import tempfile
import unittest
import zipfile

import helpers  # noqa: F401  (sys.path)
import netfetch
import osvfeed
from feedlib import FeedError

netfetch.RETRY_DELAY = 0

UBU = osvfeed.Release("ubuntu-24.04", "ubuntu", "Ubuntu:24.04:LTS", "noble")
ESM = osvfeed.Release("ubuntu-24.04-esm", "ubuntu", "Ubuntu:Pro:24.04:LTS", "noble", esm=True)
DEB = osvfeed.Release("debian-12", "debian", "Debian:12", "bookworm", snapshot="20230611T000000Z")
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"       # 8.1
CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"       # 9.8
CVSS_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"        # 5.4


def affected(eco, name, events, versions=None, availability=None):
    entry = {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if versions is not None:
        entry["versions"] = versions
    if availability is not None:
        entry["ecosystem_specific"] = {"availability": availability}
    return entry


def record(rid, affected_list, upstream=None, severity=None, published="2026-01-10T00:00:00Z",
           modified="2026-01-11T00:00:00Z", withdrawn=None):
    rec = {"id": rid, "published": published, "modified": modified, "affected": affected_list}
    if upstream is not None:
        rec["upstream"] = upstream
    if severity is not None:
        rec["severity"] = severity
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def write_zip(path, records):
    with zipfile.ZipFile(path, "w") as archive:
        for rec in records:
            archive.writestr(rec["id"] + ".json", json.dumps(rec))


def fixed(v):
    return [{"introduced": "0"}, {"fixed": v}]


class RangeShapes(unittest.TestCase):
    def test_known_shapes(self):
        self.assertEqual(osvfeed.range_pairs({"ranges": [{"type": "ECOSYSTEM", "events": fixed("1.2-1")}]}),
                         [("0", "1.2-1")])
        self.assertEqual(osvfeed.range_pairs({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}),
                         [])
        multi = [{"introduced": "0"}, {"fixed": "1.0-1"}, {"introduced": "2.0-1"}, {"fixed": "2.0-3"},
                 {"introduced": "3.0-1"}]
        self.assertEqual(osvfeed.range_pairs({"ranges": [{"type": "ECOSYSTEM", "events": multi}]}),
                         [("0", "1.0-1"), ("2.0-1", "2.0-3")])

    def test_unknown_shapes_raise(self):
        bad = [
            {"ranges": []},
            {},
            {"ranges": [{"type": "GIT", "events": fixed("abc")}]},
            {"ranges": [{"type": "SEMVER", "events": fixed("1.0.0")}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.0"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"limit": "1.0"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"introduced": "1"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "1.0"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": []}]},
        ]
        for entry in bad:
            with self.subTest(entry=entry):
                with self.assertRaises(osvfeed.ShapeError):
                    osvfeed.range_pairs(entry)


class IngestAndResolve(unittest.TestCase):
    """ingest() then resolve() for one release, with an in-memory archive and baseline."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-osv-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_release(self, release, records, archive, baseline, info_extra=None):
        path = os.path.join(self.tmp, "all.zip")
        write_zip(path, records)
        log = helpers_log()
        cands, info, stats, shapes, newest = osvfeed.ingest(path, [release], log)
        if info_extra:
            info.update(info_extra)
        counters, decisions = collections.Counter(), collections.Counter()
        rows, _, self.dropped = osvfeed.resolve(release, cands[release.key], info, archive, baseline, counters,
                                                decisions)
        return {(r["source"], r["fixed"]): r for r in rows}, counters, decisions, stats, shapes, newest

    def test_unfixed_rows_dropped(self):
        rows, _, _, stats, _, _ = self.run_release(UBU, [
            record("UBUNTU-CVE-2026-0001", [affected("Ubuntu:24.04:LTS", "openssl", [{"introduced": "0"}])],
                   upstream=["CVE-2026-0001"], severity=[{"type": "Ubuntu", "score": "high"}])],
            {"openssl": "3.0.13-0ubuntu3.6"}, {"openssl": "3.0.13-0ubuntu3"})
        self.assertEqual(rows, {})
        self.assertEqual(stats["ubuntu-24.04: unfixed (dropped)"], 1)

    def test_date_shaped_fixed_rejected(self):
        # UBUNTU-CVE-2024-6716 (tiff) really has fixed "2024-08-16".
        rows, counters, _, _, _, _ = self.run_release(UBU, [
            record("UBUNTU-CVE-2024-6716", [affected("Ubuntu:24.04:LTS", "tiff", fixed("2024-08-16"),
                                                     versions=["4.5.1+git230720-4ubuntu2"])],
                   upstream=["CVE-2024-6716"], severity=[{"type": "Ubuntu", "score": "high"}])],
            {"tiff": "4.5.1+git230720-4ubuntu2.5"}, {"tiff": "4.5.1+git230720-4ubuntu2"})
        self.assertEqual(rows, {})
        self.assertEqual(counters["rejected: date-shaped"], 1)

    def test_invalid_and_tokenless_fixed_rejected(self):
        rows, counters, _, _, _, _ = self.run_release(UBU, [
            record("UBUNTU-CVE-2026-0002", [affected("Ubuntu:24.04:LTS", "zlib", fixed("not_a_version")),
                                            affected("Ubuntu:24.04:LTS", "curl", fixed("99.1-1"),
                                                     versions=["8.5.0-2ubuntu10"])],
                   upstream=["CVE-2026-0002"], severity=[{"type": "Ubuntu", "score": "high"}])],
            {"zlib": "1:1.3.dfsg-3.1ubuntu2.1", "curl": "8.5.0-2ubuntu10.6"},
            {"zlib": "1:1.3.dfsg-3.1ubuntu2", "curl": "8.5.0-2ubuntu10"})
        self.assertEqual(rows, {})
        self.assertEqual(counters["rejected: not a Debian version"], 1)
        self.assertEqual(counters["rejected: no shared leading token"], 1)

    def test_token_check_allows_jumps_inside_the_release(self):
        # chromium 130 sits between the release-day 114 and today's 142: a real (old) fix, kept.
        recs = [record("DEBIAN-CVE-2026-0009", [affected("Debian:12", "chromium", fixed("130.0.6723.58-1~deb12u1"),
                                                         versions=["129.0.6668.89-1~deb12u1"])],
                       upstream=["CVE-2026-0009"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}])]
        rows, counters, _, _, _, _ = self.run_release(DEB, recs, {"chromium": "142.0.7444.59-1~deb12u1"},
                                                      {"chromium": "114.0.5735.90-2"})
        self.assertEqual(list(rows), [("chromium", "130.0.6723.58-1~deb12u1")])
        self.assertEqual(counters["rejected"], 0)

    def test_token_check_open_ended_for_esm(self):
        # clamav 1.4 for focal ESM while the free archive has 0.103: kept in the ESM file only.
        rec = record("UBUNTU-CVE-2025-20234", [affected(
            "Ubuntu:Pro:20.04:LTS", "clamav", fixed("1.4.3+dfsg-0ubuntu0.20.04.1+esm1"),
            availability="Available with Ubuntu Pro: https://ubuntu.com/pro")],
            upstream=["CVE-2025-20234"], severity=[{"type": "Ubuntu", "score": "high"}])
        esm = osvfeed.Release("ubuntu-20.04-esm", "ubuntu", "Ubuntu:Pro:20.04:LTS", "focal", esm=True)
        rows, counters, _, _, _, _ = self.run_release(esm, [rec], {"clamav": "0.103.12+dfsg-0ubuntu0.20.04.1"},
                                                      {"clamav": "0.102.2+dfsg-2ubuntu1"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(counters["rejected"], 0)

    def test_dropped_rows_kept_for_review(self):
        recs = [record("DEBIAN-CVE-2026-0013", [affected("Debian:12", "sed", fixed("4.9-1+deb12u1"))],
                       upstream=["CVE-2026-0013"], severity=[{"type": "CVSS_V3", "score": CVSS_MED}])]
        self.run_release(DEB, recs, {"sed": "4.9-1+deb12u1"}, {"sed": "4.9-1"})
        self.assertEqual(self.dropped, [["sed", "0", "4.9-1+deb12u1", "below High (dropped)", 2]])

    def test_published_check_against_fake_archive(self):
        recs = [record("DEBIAN-CVE-2026-0003", [
            affected("Debian:12", "apt", fixed("2.6.2")),           # archive has 2.6.2: ships
            affected("Debian:12", "gzip", fixed("1.12-1+deb12u1")),  # archive only 1.12-1: not published
            affected("Debian:12", "ghost", fixed("1.0-2")),          # not in the archive at all
        ], upstream=["CVE-2026-0003"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}])]
        rows, counters, _, _, _, _ = self.run_release(
            DEB, recs, {"apt": "2.6.2", "gzip": "1.12-1"}, {"apt": "2.6.1", "gzip": "1.12-1"})
        self.assertEqual(sorted(rows), [("apt", "2.6.2")])
        self.assertEqual(counters["unpublished: archive below fixed"], 1)
        self.assertEqual(counters["unpublished: source not in the archive"], 1)

    def test_esm_skips_the_published_check(self):
        recs = [record("UBUNTU-CVE-2026-0004", [affected(
            "Ubuntu:Pro:24.04:LTS", "libxml2", fixed("2.9.14+dfsg-1.3ubuntu3.4+esm1"),
            availability="Available with Ubuntu Pro: https://ubuntu.com/pro")],
            upstream=["CVE-2026-0004"], severity=[{"type": "Ubuntu", "score": "high"}])]
        rows, counters, _, _, _, _ = self.run_release(ESM, recs, {"libxml2": "2.9.14+dfsg-1.3ubuntu3.3"},
                                                      {"libxml2": "2.9.14+dfsg-1.3ubuntu3"})
        self.assertEqual(list(rows), [("libxml2", "2.9.14+dfsg-1.3ubuntu3.4+esm1")])
        self.assertEqual(counters["published check skipped (ESM archive needs a token)"], 1)

    def test_pro_rows_never_in_the_free_file(self):
        recs = [record("UBUNTU-CVE-2026-0005", [affected(
            "Ubuntu:24.04:LTS", "libxml2", fixed("2.9.14+dfsg-1.3ubuntu3.4+esm1"),
            availability="Available with Ubuntu Pro: https://ubuntu.com/pro")],
            upstream=["CVE-2026-0005"], severity=[{"type": "Ubuntu", "score": "high"}])]
        rows, _, _, stats, _, _ = self.run_release(UBU, recs, {"libxml2": "9"}, {})
        self.assertEqual(rows, {})
        self.assertEqual(stats["ubuntu-24.04: excluded (Ubuntu Pro only)"], 1)

    def test_unknown_availability_is_an_unknown_shape(self):
        recs = [record("UBUNTU-CVE-2026-0006", [affected("Ubuntu:24.04:LTS", "xx", fixed("1.0-1"),
                                                         availability="Some new subscription")],
                       upstream=["CVE-2026-0006"])]
        _, _, _, stats, shapes, _ = self.run_release(UBU, recs, {"xx": "1.0-1"}, {})
        self.assertEqual(stats["ubuntu-24.04: unknown range shape"], 1)
        self.assertIn("availability", shapes[0])

    def test_baseline_cut(self):
        # openssh 1:3.0.1 (2001) is below the release-day 1:9.2p1-2: cut. 1:9.2p1-2+deb12u3 ships.
        recs = [record("DEBIAN-CVE-2001-0001", [affected("Debian:12", "openssh", fixed("1:3.0.1"))],
                       upstream=["CVE-2001-0001"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}]),
                record("DEBIAN-CVE-2026-0007", [affected("Debian:12", "openssh", fixed("1:9.2p1-2+deb12u3"))],
                       upstream=["CVE-2026-0007"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}]),
                record("DEBIAN-CVE-2026-0008", [affected("Debian:12", "openssh", fixed("1:9.2p1-2"))],
                       upstream=["CVE-2026-0008"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}])]
        rows, counters, _, _, _, _ = self.run_release(DEB, recs, {"openssh": "1:9.2p1-2+deb12u7"},
                                                      {"openssh": "1:9.2p1-2"})
        self.assertEqual(sorted(rows), [("openssh", "1:9.2p1-2+deb12u3")])
        self.assertEqual(counters["baseline cut"], 2)

    def test_severity_chains_and_decisions(self):
        recs = [
            # Ubuntu priority beats a critical CVSS.
            record("UBUNTU-CVE-2026-0010", [affected("Ubuntu:24.04:LTS", "aa", fixed("1.0-1ubuntu0.1"))],
                   upstream=["CVE-2026-0010"], severity=[{"type": "Ubuntu", "score": "low"},
                                                         {"type": "CVSS_V3", "score": CVSS_CRIT}]),
            # No priority: CVSS decides.
            record("UBUNTU-CVE-2026-0011", [affected("Ubuntu:24.04:LTS", "bb", fixed("1.0-1ubuntu0.1"))],
                   upstream=["CVE-2026-0011"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}]),
            # Nothing: Medium, dropped.
            record("UBUNTU-CVE-2026-0012", [affected("Ubuntu:24.04:LTS", "cc", fixed("1.0-1ubuntu0.1"))],
                   upstream=["CVE-2026-0012"]),
        ]
        archive = {k * 2: "1.0-1ubuntu0.1" for k in "abc"}
        rows, counters, decisions, _, _, _ = self.run_release(UBU, recs, archive, {})
        self.assertEqual(sorted(rows), [("bb", "1.0-1ubuntu0.1")])
        self.assertEqual(rows[("bb", "1.0-1ubuntu0.1")]["severity"], 4)
        self.assertEqual(decisions, {"ubuntu priority": 1, "cvss": 1, "default medium": 1})

    def test_debian_chain_advisory_means_high(self):
        recs = [
            # No CVSS anywhere, but a DSA ships the fix: High.
            record("DEBIAN-CVE-2026-0020", [affected("Debian:12", "xx", fixed("1.0-1+deb12u1"))],
                   upstream=["CVE-2026-0020"]),
            record("DSA-6001-1", [affected("Debian:12", "xx", fixed("1.0-1+deb12u1"))],
                   upstream=["CVE-2026-0020"], published="2026-02-01T00:00:00Z"),
            # No CVSS and no advisory: Medium (hidden).
            record("DEBIAN-CVE-2026-0021", [affected("Debian:12", "yy", fixed("1.0-1+deb12u1"))],
                   upstream=["CVE-2026-0021"]),
            # CVSS Medium beats the advisory rule.
            record("DEBIAN-CVE-2026-0022", [affected("Debian:12", "zz", fixed("1.0-1+deb12u1"))],
                   upstream=["CVE-2026-0022"], severity=[{"type": "CVSS_V3", "score": CVSS_MED}]),
            record("DLA-4001-1", [affected("Debian:12", "zz", fixed("1.0-1+deb12u1"))], upstream=["CVE-2026-0022"]),
        ]
        archive = {k * 2: "1.0-1+deb12u1" for k in "xyz"}
        rows, _, decisions, _, _, _ = self.run_release(DEB, recs, archive, {})
        self.assertEqual(sorted(rows), [("xx", "1.0-1+deb12u1")])
        self.assertEqual(rows[("xx", "1.0-1+deb12u1")]["date"], "2026-02-01")
        self.assertEqual(rows[("xx", "1.0-1+deb12u1")]["dateSource"], "advisory")
        self.assertEqual(decisions, {"dsa/dla exists -> high": 1, "default medium": 1, "cvss": 1})

    def test_ids_merge_and_low_ids_are_left_out(self):
        recs = [
            record("UBUNTU-CVE-2026-0030", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.7"))],
                   upstream=["CVE-2026-0030"], severity=[{"type": "Ubuntu", "score": "high"}]),
            record("UBUNTU-CVE-2026-0031", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.7"))],
                   upstream=["CVE-2026-0031"], severity=[{"type": "Ubuntu", "score": "low"}]),
            record("UBUNTU-CVE-2026-0032", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.7"))],
                   upstream=["CVE-2026-0032"], severity=[{"type": "Ubuntu", "score": "critical"}]),
            record("USN-8000-1", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.7"))],
                   upstream=["CVE-2026-0030", "CVE-2026-0031", "CVE-2026-0032"], published="2026-03-03T00:00:00Z"),
        ]
        rows, _, _, _, _, _ = self.run_release(UBU, recs, {"openssl": "3.0.13-0ubuntu3.7"},
                                               {"openssl": "3.0.13-0ubuntu3"})
        row = rows[("openssl", "3.0.13-0ubuntu3.7")]
        self.assertEqual(row["ids"], ["CVE-2026-0030", "CVE-2026-0032"])
        self.assertEqual(row["severity"], 4)
        self.assertEqual(row["date"], "2026-03-03")

    def test_fix_date_is_the_earliest_advisory_else_the_earliest_record(self):
        # S7c: two DSAs name one fix (a re-issue, then the original): the row, and the file's 5th element, take
        # the EARLIEST advisory, never the CVE record's older date. With no advisory the intermediate keeps the
        # earliest record date, but the file ships null (review M1: a CVE record's date is the disclosure).
        recs = [
            record("DEBIAN-CVE-2026-0040", [affected("Debian:12", "xx", fixed("1.0-1+deb12u1"))],
                   upstream=["CVE-2026-0040"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}],
                   published="2025-12-01T00:00:00Z"),
            record("DSA-6002-2", [affected("Debian:12", "xx", fixed("1.0-1+deb12u1"))], upstream=["CVE-2026-0040"],
                   published="2026-03-09T10:00:00Z"),
            record("DSA-6002-1", [affected("Debian:12", "xx", fixed("1.0-1+deb12u1"))], upstream=["CVE-2026-0040"],
                   published="2026-03-02T10:00:00Z"),
            record("DEBIAN-CVE-2026-0041", [affected("Debian:12", "yy", fixed("2.0-1+deb12u1"))],
                   upstream=["CVE-2026-0041"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}],
                   published="2026-02-20T00:00:00Z"),
            record("DEBIAN-CVE-2026-0042", [affected("Debian:12", "yy", fixed("2.0-1+deb12u1"))],
                   upstream=["CVE-2026-0042"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}],
                   published="2026-02-10T00:00:00Z"),
            record("DEBIAN-CVE-2026-0043", [affected("Debian:12", "zz", fixed("3.0-1+deb12u1"))],
                   upstream=["CVE-2026-0043"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}], published=None),
        ]
        archive = {"xx": "1.0-1+deb12u1", "yy": "2.0-1+deb12u1", "zz": "3.0-1+deb12u1"}
        rows, _, _, _, _, _ = self.run_release(DEB, recs, archive, {})
        self.assertEqual(rows[("xx", "1.0-1+deb12u1")]["date"], "2026-03-02")
        self.assertEqual(rows[("yy", "2.0-1+deb12u1")]["date"], "2026-02-10")
        self.assertEqual(rows[("yy", "2.0-1+deb12u1")]["dateSource"], "record")
        self.assertIsNone(rows[("zz", "3.0-1+deb12u1")]["date"])
        body = osvfeed.release_body(DEB, list(rows.values()))
        self.assertEqual(body["pkgs"], {
            "xx": [["0", "1.0-1+deb12u1", 3, ["CVE-2026-0040"], "2026-03-02"]],
            "yy": [["0", "2.0-1+deb12u1", 3, ["CVE-2026-0041", "CVE-2026-0042"], None]],
            "zz": [["0", "3.0-1+deb12u1", 3, ["CVE-2026-0043"], None]]})
        osvfeed.check_release_body(json.loads(osvfeed.body_bytes(body)), "debian-12",
                                   {"format": "dpkg", "file": "x", "rows": 3})

    def test_withdrawn_records_skipped(self):
        recs = [record("UBUNTU-CVE-2026-0040", [affected("Ubuntu:24.04:LTS", "xx", fixed("1.0-1"))],
                       upstream=["CVE-2026-0040"], severity=[{"type": "Ubuntu", "score": "high"}],
                       withdrawn="2026-04-01T00:00:00Z")]
        rows, _, _, stats, _, _ = self.run_release(UBU, recs, {"xx": "1.0-1"}, {})
        self.assertEqual(rows, {})
        self.assertEqual(stats["withdrawn records skipped"], 1)

    def test_newest_modified(self):
        recs = [record("UBUNTU-CVE-2026-0041", [], modified="2026-05-01T10:00:00.123456789Z"),
                record("UBUNTU-CVE-2026-0042", [], modified="2026-05-01T10:00:00.9Z")]
        *_, newest = self.run_release(UBU, recs, {}, {})
        self.assertEqual(newest, "2026-05-01T10:00:00.9Z")


class KernelFold(unittest.TestCase):
    def test_fold(self):
        rows = [
            {"source": "linux-aws-6.8", "introduced": "0", "fixed": "6.8.0-1040.42~22.04.1", "severity": 3,
             "ids": ["CVE-2026-1", "CVE-2026-2"], "kernel": True, "date": "2026-10-30"},
            {"source": "linux-aws-6.8", "introduced": "0", "fixed": "6.8.0-1038.40~22.04.1", "severity": 4,
             "ids": ["CVE-2026-3"], "kernel": True, "date": "2026-10-01"},
            {"source": "linuxptp", "introduced": "0", "fixed": "4.0-1ubuntu0.1", "severity": 3,
             "ids": ["CVE-2026-4"], "kernel": False, "date": "2026-09-01", "dateSource": "advisory"},
        ]
        body = osvfeed.release_body(UBU, rows)
        self.assertEqual(body["kernel"], {"linux-aws-6.8": [["0", "6.8.0-1038.40~22.04.1", 4, 1, "2026-10-01"],
                                                               ["0", "6.8.0-1040.42~22.04.1", 3, 2, "2026-10-30"]]})
        self.assertEqual(body["pkgs"], {"linuxptp": [["0", "4.0-1ubuntu0.1", 3, ["CVE-2026-4"], "2026-09-01"]]})
        self.assertEqual(osvfeed.row_count(body), 3)

    def test_kernel_names(self):
        for name in ("linux", "linux-aws", "linux-aws-6.8", "linux-hwe-6.8", "linux-raspi-realtime"):
            self.assertTrue(osvfeed.is_kernel(name), name)
        for name in ("linuxptp", "linux-firmware", "linux-firmware-raspi", "linux-base", "linux-atm", "util-linux"):
            self.assertFalse(osvfeed.is_kernel(name), name)


class Archive(unittest.TestCase):
    def test_parse_sources(self):
        text = ("Package: apt\nVersion: 2.6.1\n\nPackage: apt\nVersion: 2.6.2\n\n"
                "Package: gcc-12\nVersion: 12.1.0-1\nExtra-Source-Only: yes\n\nPackage: gcc-12\nVersion: 12.2.0-14\n")
        self.assertEqual(osvfeed.parse_sources(io.StringIO(text)), {"apt": "2.6.2", "gcc-12": "12.2.0-14"})

    def test_parse_release_prefers_sha256(self):
        data = (b"Origin: Debian\nDate: Sat, 10 Jun 2023 08:51:17 UTC\nSHA256:\n"
                b" " + b"a" * 64 + b" 10 main/source/Sources.xz\n"
                b" " + b"b" * 64 + b" 20 main/binary-amd64/Packages.xz\n"
                b"SHA512:\n " + b"c" * 128 + b" 10 main/source/Sources.xz\n")
        date, files = osvfeed.parse_release(data)
        self.assertEqual(date, "2023-06-10T08:51:17Z")
        self.assertEqual(files, {"main/source/Sources.xz": ("sha256", "a" * 64, 10)})
        date, files = osvfeed.parse_release(b"Date: Thu, 15 Oct 2026 12:18:34 UTC\nSHA512:\n "
                                            + b"C" * 128 + b" 10 universe/source/Sources.xz\n")
        self.assertEqual(files, {"universe/source/Sources.xz": ("sha512", "c" * 128, 10)})


class Golden(unittest.TestCase):
    def row(self, source, fixed, date="2026-10-01", source_kind="advisory", modified="2026-10-02", intro="0",
            rule="cvss"):
        return {"source": source, "introduced": intro, "fixed": fixed, "severity": 3, "ids": ["CVE-2026-1"],
                "kernel": False, "date": date, "dateSource": source_kind, "modified": modified,
                "rules": {"CVE-2026-1": rule}}

    def test_capture_date_filter(self):
        inventory = {"apt": "2.6.1", "glibc": "2.36-9+deb12u10", "curl": "7.88.1-10+deb12u5"}
        rows = [self.row("apt", "2.6.2", date="2026-11-04"),
                self.row("glibc", "2.36-9+deb12u14", date="2026-11-06"),          # after capture: not counted
                self.row("curl", "7.88.1-10+deb12u4")]                              # installed is newer
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05"), ({"apt": ["2.6.2"]}, []))

    def test_archive_at_capture_keeps_fixtures_frozen(self):
        # An old CVE whose fix OSV records after the capture: dated 2025, but not in the archive at capture.
        inventory = {"apt": "2.6.1", "curl": "7.88.1-10+deb12u5"}
        rows = [self.row("apt", "2.6.2", date="2026-11-04"),
                self.row("curl", "7.88.1-10+deb12u6", date="2025-01-01", source_kind="record")]
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05")[0],
                         {"apt": ["2.6.2"], "curl": ["7.88.1-10+deb12u6"]})
        at_capture = {"apt": "2.6.2", "curl": "7.88.1-10+deb12u5"}
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05", at_capture), ({"apt": ["2.6.2"]}, []))
        # A would-be hit on a source the frozen archive does not list is reported, not silently skipped.
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05", {"curl": "9"}),
                         ({"curl": ["7.88.1-10+deb12u6"]}, ["apt 2.6.2"]))

    def test_introduced_respected(self):
        rows = [self.row("xx", "2.0-3", intro="2.0-1")]
        self.assertEqual(osvfeed.golden_hits(rows, {"xx": "1.9-1"}, "2026-11-05")[0], {})
        self.assertEqual(osvfeed.golden_hits(rows, {"xx": "2.0-2"}, "2026-11-05")[0], {"xx": ["2.0-3"]})

    def test_inventory_parsing(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "inv.tsv")
        with open(path, "w") as handle:
            handle.write("ii \tbsdutils\t1:2.39.3-9ubuntu6.6\tutil-linux\t2.39.3-9ubuntu6.6\n"
                         "rc \told\t1.0\told\t1.0\n"
                         "ii \tlinux-modules-6.8.0-1040\t6.8.0-1040.42\tlinux-aws-6.8\t6.8.0-1040.42\n"
                         "ii \tlinux-modules-6.8.0-1038\t6.8.0-1038.40\tlinux-aws-6.8\t6.8.0-1038.40\n")
        self.assertEqual(osvfeed.read_inventory(path),
                         {"util-linux": "2.39.3-9ubuntu6.6", "linux-aws-6.8": "6.8.0-1040.42"})

    def test_real_fixtures_are_small_and_parse(self):
        directory = osvfeed.GOLDEN_DIR
        cases = osvfeed.golden_cases(directory)
        self.assertEqual({c["fixture"] for c in cases},
                         {"ubuntu-24.04-stock.tsv", "debian-12-stock.tsv", "debian-12.0-20230612.tsv",
                          "alpine-3.20-stock.apk.txt", "alpine-3.20.0-20240522.apk.txt",
                          "alpine-3.24-stock.apk.txt", "almalinux-9-stock.rpm.tsv", "almalinux-9.2-20230718.rpm.tsv",
                          "rockylinux-9.3-20231128.rpm.tsv", "rockylinux-9-resf-stock.rpm.tsv",
                          "rockylinux-8-modules-current.rpm.tsv", "rockylinux-8-httpd-behind.rpm.tsv",
                          "synthetic-alma-9-php82-module-current.rpm.tsv",
                          "synthetic-alma-9-php82-module-behind.rpm.tsv"})
        for case in cases:
            if osvfeed.FORMAT_OF[case["release"]] in ("apk", "rpm"):
                continue    # tests/test_alpine.py, tests/test_rpm.py
            for name in (case["fixture"], case["archive"]):
                path = os.path.join(directory, name)
                self.assertLess(os.path.getsize(path), 64 * 1024, path)
                self.assertTrue(osvfeed.read_inventory(path))
            # Every fixture source has a frozen archive version (stock images: all from the archive).
            self.assertLessEqual(set(osvfeed.read_inventory(os.path.join(directory, case["fixture"]))),
                                 set(osvfeed.read_inventory(os.path.join(directory, case["archive"]))))

    def write_case(self, tmp, **case):
        with open(os.path.join(tmp, "inv.tsv"), "w") as handle:
            handle.write("apt\t2.6.1\nsed\t4.9-1\npcre2\t10.42-1\n")
        with open(os.path.join(tmp, "inv.archive.tsv"), "w") as handle:
            handle.write("apt\t2.6.2\nsed\t4.9-1+deb12u1\npcre2\t10.42-1+deb12u2\n")
        base = {"fixture": "inv.tsv", "release": "debian-12", "capture": "2026-11-05", "archive": "inv.archive.tsv"}
        base.update(case)
        with open(os.path.join(tmp, "expected.json"), "w") as handle:
            json.dump({"cases": [base]}, handle)

    def test_extra_hits_fail_when_many_or_heuristic(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.write_case(tmp, exact=["apt"])
        with open(os.path.join(tmp, "inv.tsv"), "a") as handle:
            handle.write("tar\t1.34+dfsg-1.2\n")
        with open(os.path.join(tmp, "inv.archive.tsv"), "a") as handle:
            handle.write("tar\t1.34+dfsg-1.2+deb12u1\n")
        apt, sed = self.row("apt", "2.6.2"), self.row("sed", "4.9-1+deb12u1")
        pcre2, tar = self.row("pcre2", "10.42-1+deb12u2"), self.row("tar", "1.34+dfsg-1.2+deb12u1")
        log = helpers_log()
        self.assertEqual(osvfeed.check_golden("debian-12", [apt, sed, pcre2], log, tmp), [], "2 extra: warn")
        self.assertTrue(any("also flags ['pcre2', 'sed']" in w for w in log.warnings))
        failures = osvfeed.check_golden("debian-12", [apt, sed, pcre2, tar], log, tmp)
        self.assertIn("3 unexpected sources flagged", failures[0])
        heuristic = self.row("sed", "4.9-1+deb12u1", rule="dsa/dla exists -> high")
        failures = osvfeed.check_golden("debian-12", [apt, heuristic], log, tmp)
        self.assertIn("rated High by a heuristic rule, not a score: sed (dsa/dla exists -> high)", failures[0])
        package = self.row("sed", "4.9-1+deb12u1", rule="ubuntu package priority")
        self.assertTrue(osvfeed.check_golden("debian-12", [apt, package], log, tmp))

    def test_check_golden_errors_and_warnings(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        log = helpers_log()
        self.write_case(tmp, atLeast=["apt", "sed"])
        self.assertEqual(osvfeed.check_golden("debian-12", [self.row("apt", "2.6.2"), self.row("sed", "4.9-1+deb12u1")],
                                              log, tmp), [])
        self.assertEqual(osvfeed.check_golden("ubuntu-24.04", [], log, tmp), [], "other releases' cases skipped")
        missing = osvfeed.check_golden("debian-12", [self.row("apt", "2.6.2")], log, tmp)
        self.assertEqual(len(missing), 1)
        self.assertIn("missing ['sed']", missing[0])
        # exact: an extra hit (OSV re-rated pcre2's Medium fix to High) is a WARNING, a missing one an error.
        self.write_case(tmp, exact=["apt"])
        log = helpers_log()
        self.assertEqual(osvfeed.check_golden("debian-12", [self.row("apt", "2.6.2"),
                                                            self.row("pcre2", "10.42-1+deb12u2")], log, tmp), [])
        self.assertTrue(any("also flags ['pcre2']" in w for w in log.warnings), log.warnings)
        self.assertIn("missing ['apt']", osvfeed.check_golden("debian-12", [], log, tmp)[0])
        # A hit on a source the frozen archive file lacks is an error.
        unarchived = osvfeed.check_golden("debian-12", [self.row("apt", "2.6.2"), self.row("zstd", "1.5.4-2+deb12u1")],
                                          log, tmp)
        self.assertEqual(unarchived, [])  # zstd is not installed: no hit at all
        with open(os.path.join(tmp, "inv.tsv"), "a") as handle:
            handle.write("zstd\t1.5.4-2\n")
        unarchived = osvfeed.check_golden("debian-12", [self.row("apt", "2.6.2"), self.row("zstd", "1.5.4-2+deb12u1")],
                                          log, tmp)
        self.assertIn("not in inv.archive.tsv", unarchived[0])


class RowGates(unittest.TestCase):
    def gate(self, rows, previous, minimum=1, overrides=(), today="2026-11-05"):
        return osvfeed.row_gate("debian-12", rows, previous, minimum, list(overrides), today, helpers_log())

    def test_first_build_uses_the_committed_minimum(self):
        self.assertIsNone(self.gate(500, None, minimum=400))
        self.assertIn("under the floor 400", self.gate(399, None, minimum=400))

    def test_swing(self):
        self.assertIsNone(self.gate(1290, 1000))
        self.assertIsNone(self.gate(710, 1000))
        self.assertIn("1000 -> 1301", self.gate(1301, 1000))
        self.assertIn("1000 -> 699", self.gate(699, 1000))

    def test_small_files_cannot_go_to_zero(self):
        # The 25-row swing floor would allow 6 -> 0; the half-of-previous floor (and the minimum) refuse it.
        self.assertIsNone(self.gate(30, 6))
        self.assertIn("under the floor 3", self.gate(0, 6))
        self.assertIn("under the floor 3", self.gate(2, 6))
        self.assertIn("under the floor 3", self.gate(0, None, minimum=3))

    def test_override(self):
        live = {"release": "debian-12", "min": 100, "max": 3000, "expires": "2026-11-30", "reason": "DSA backlog"}
        self.assertIsNone(self.gate(2500, 1000, overrides=[live]))
        self.assertIn("outside the override", self.gate(50, 1000, overrides=[live]))
        expired = dict(live, expires="2026-11-04")
        self.assertIn("1000 -> 2500", self.gate(2500, 1000, overrides=[expired]))
        other = dict(live, release="debian-13")
        self.assertIn("1000 -> 2500", self.gate(2500, 1000, overrides=[other]))

    def test_committed_gates_are_valid(self):
        minimums, overrides = osvfeed.load_gates()
        self.assertEqual(set(minimums), set(osvfeed.RELEASE_KEYS))
        self.assertIsInstance(overrides, list)

    def test_bad_gates_are_config_errors(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        good_min = {"minimums": {k: 1 for k in osvfeed.RELEASE_KEYS}}
        for minimums, overrides in (({"minimums": {"debian-12": 1}}, {"rowCount": []}),
                                    (good_min, {"rowCount": [{"release": "debian-12", "min": 5, "max": 1,
                                                              "expires": "2026-12-01", "reason": "x"}]}),
                                    (good_min, {"rowCount": [{"release": "debian-12", "min": 1, "max": 5,
                                                              "expires": "soon", "reason": "x"}]})):
            with open(os.path.join(tmp, "minimums.json"), "w") as handle:
                json.dump(minimums, handle)
            with open(os.path.join(tmp, "overrides.json"), "w") as handle:
                json.dump(overrides, handle)
            with self.assertRaises(osvfeed.ConfigError):
                osvfeed.load_gates(tmp)

    def test_gone_needs_retired(self):
        previous = {"debian-12": {}, "ubuntu-25.10": {}}
        with self.assertRaisesRegex(osvfeed.ConfigError, "ubuntu-25.10"):
            osvfeed.check_gone(previous)
        osvfeed.check_gone(previous, retired=("ubuntu-25.10",))
        with self.assertRaisesRegex(osvfeed.ConfigError, "both"):
            osvfeed.check_gone(previous, retired=("debian-12",))


class ReleaseBody(unittest.TestCase):
    def test_schema_check(self):
        rows = [{"source": "apt", "introduced": "0", "fixed": "2.6.2", "severity": 3, "ids": ["CVE-2026-109518"],
                 "kernel": False, "date": "2026-11-04"}]
        body = osvfeed.release_body(DEB, rows)
        entry = {"format": "dpkg", "file": "r/debian-12-x.json", "rows": 1}
        osvfeed.check_release_body(json.loads(osvfeed.body_bytes(body)), "debian-12", entry)
        bad = json.loads(osvfeed.body_bytes(body))
        bad["pkgs"]["apt"][0][2] = 2
        with self.assertRaisesRegex(FeedError, "not High or Critical"):
            osvfeed.check_release_body(bad, "debian-12", entry)
        bad = json.loads(osvfeed.body_bytes(body))
        bad["pkgs"]["apt"][0][1] = "2024-08-16"
        with self.assertRaisesRegex(FeedError, "bad version"):
            osvfeed.check_release_body(bad, "debian-12", entry)
        with self.assertRaisesRegex(FeedError, "manifest says 2"):
            osvfeed.check_release_body(json.loads(osvfeed.body_bytes(body)), "debian-12", dict(entry, rows=2))
        bad = json.loads(osvfeed.body_bytes(body))
        bad["command"] = "rm -rf /"
        with self.assertRaisesRegex(FeedError, "keys must be"):
            osvfeed.check_release_body(bad, "debian-12", entry)

    def test_fix_date_element(self):
        # S7c: a package row is 4 fields (a pre-S7c file) or 5, the 5th a real YYYY-MM-DD day or null.
        rows = [{"source": "apt", "introduced": "0", "fixed": "2.6.2", "severity": 4,
                 "ids": ["CVE-2026-10001", "CVE-2026-10002"], "kernel": False, "date": "2026-11-04",
                 "dateSource": "advisory"}]
        body = json.loads(osvfeed.body_bytes(osvfeed.release_body(DEB, rows)))
        # S7c only appends: the first 4 elements (all the shipped app reads) are as before.
        self.assertEqual(body["pkgs"]["apt"], [["0", "2.6.2", 4, ["CVE-2026-10001", "CVE-2026-10002"], "2026-11-04"]])
        record_only = dict(rows[0], dateSource="record")
        self.assertEqual(osvfeed.release_body(DEB, [record_only])["pkgs"]["apt"][0][4], None, "review M1")
        entry = {"format": "dpkg", "file": "r/debian-12-x.json", "rows": 1}
        for good in ("2026-11-04", None, "drop"):
            ok = json.loads(json.dumps(body))
            if good == "drop":
                ok["pkgs"]["apt"][0].pop()
            else:
                ok["pkgs"]["apt"][0][4] = good
            osvfeed.check_release_body(ok, "debian-12", entry)
        for value in ("2026-13-01", "2026-02-30", "2026-11-4", "2026-11-04\n", "2026-11-04T00:00:00Z",
                      "\u0662\u0660\u0662\u0666-11-04", "", 20261104, True, ["2026-11-04"]):
            with self.subTest(value=value):
                bad = json.loads(json.dumps(body))
                bad["pkgs"]["apt"][0][4] = value
                with self.assertRaisesRegex(FeedError, "bad fix date"):
                    osvfeed.check_release_body(bad, "debian-12", entry)
        bad = json.loads(json.dumps(body))
        bad["pkgs"]["apt"][0].append("2026-11-04")
        with self.assertRaisesRegex(FeedError, "is not 4 or 5 fields"):
            osvfeed.check_release_body(bad, "debian-12", entry)
        bad = json.loads(json.dumps(body))
        bad["pkgs"]["apt"][0][4:] = []
        bad["pkgs"]["apt"][0].pop()
        with self.assertRaisesRegex(FeedError, "is not 4 or 5 fields"):
            osvfeed.check_release_body(bad, "debian-12", entry)

    def test_record_dates_are_strict(self):
        # Review L2: a date the builder takes from OSV is a real ASCII day, else None (never a refused file).
        for text, want in (("2026-11-03T10:00:00Z", "2026-11-03"), ("2026-11-03", "2026-11-03"),
                           ("2026-02-30T00:00:00Z", None), ("2026-13-01", None), ("2026-1-03", None),
                           ("20261-11-03", None), ("\u0662\u0660\u0662\u0666-11-03", None), ("", None), (None, None),
                           (20261103, None)):
            with self.subTest(text=text):
                self.assertEqual(osvfeed._date(text), want)


class EndToEnd(unittest.TestCase):
    """build_releases() over file:// mirrors: fake OSV zip + modified_id.csv, fake signed InRelease + Sources.xz."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-e2e-")
        self.addCleanup(shutil.rmtree, self.tmp)
        signer = helpers.make_gpg(self.tmp)
        if signer is None:
            self.skipTest("gpg is not installed")
        keyring, self.clearsign = signer
        self.patch(osvfeed, "ARCHIVE_KEYRINGS", {"ubuntu": keyring, "debian": keyring})
        self.mirror = os.path.join(self.tmp, "mirror")
        osv = os.path.join(self.tmp, "osv", "Ubuntu")
        os.makedirs(osv)
        for suite, sources in (("noble", "Package: openssl\nVersion: 3.0.13-0ubuntu3\n"),
                               ("noble-updates", "Package: openssl\nVersion: 3.0.13-0ubuntu3.6\n\n"
                                                 "Package: oddity\nVersion: 1.0 beta\n"),
                               ("noble-security", "Package: linux-gcp\nVersion: 6.8.0-1020.21\n")):
            self.write_suite(suite, sources)
        write_zip(os.path.join(osv, "all.zip"), [
            record("UBUNTU-CVE-2026-0050", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.6")),
                                            affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.9"))],
                   upstream=["CVE-2026-0050"], severity=[{"type": "Ubuntu", "score": "high"}]),
            record("UBUNTU-CVE-2026-0051", [affected("Ubuntu:24.04:LTS", "linux-gcp", fixed("6.8.0-1020.21"))],
                   upstream=["CVE-2026-0051"], severity=[{"type": "Ubuntu", "score": "high"}]),
            record("USN-8001-1", [affected("Ubuntu:24.04:LTS", "openssl", fixed("3.0.13-0ubuntu3.6"))],
                   upstream=["CVE-2026-0050"], published="2026-02-02T00:00:00Z",
                   modified="2026-02-03T04:05:06.123Z"),
        ])
        with open(os.path.join(osv, "modified_id.csv"), "w") as handle:
            handle.write("2026-02-03T04:05:06.123Z,USN-8001-1\n2026-01-11T00:00:00Z,UBUNTU-CVE-2026-0050\n")
        self.golden = os.path.join(self.tmp, "golden")
        os.makedirs(self.golden)
        with open(os.path.join(self.golden, "inv.tsv"), "w") as handle:
            handle.write("openssl\t3.0.13-0ubuntu3.5\n")
        with open(os.path.join(self.golden, "inv.archive.tsv"), "w") as handle:
            handle.write("openssl\t3.0.13-0ubuntu3.6\n")
        with open(os.path.join(self.golden, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.tsv", "release": "ubuntu-24.04", "capture": "2026-11-05",
                                  "archive": "inv.archive.tsv", "exact": ["openssl"]}]}, handle)
        self.gates = os.path.join(self.tmp, "gates")
        os.makedirs(self.gates)
        self.write_gates({"ubuntu-24.04": 1})
        self.patch(osvfeed, "UBUNTU_MIRROR", "file://" + self.mirror)
        self.patch(netfetch, "OSV_BASE", "file://" + os.path.join(self.tmp, "osv"))

    def write_suite(self, suite, sources, sign=True, extra=""):
        directory = os.path.join(self.mirror, "dists", suite, "main", "source")
        os.makedirs(directory, exist_ok=True)
        data = lzma.compress(sources.encode())
        with open(os.path.join(directory, "Sources.xz"), "wb") as handle:
            handle.write(data)
        digest = netfetch.hashlib.sha256(data).hexdigest()
        release = os.path.join(self.mirror, "dists", suite, "Release")
        with open(release, "w") as handle:
            handle.write(f"Suite: {suite}\nDate: Thu, 25 Apr 2024 15:10:33 UTC\n{extra}SHA256:\n"
                         f" {digest} {len(data)} main/source/Sources.xz\n")
        inrelease = os.path.join(self.mirror, "dists", suite, "InRelease")
        if sign:
            self.clearsign(release, inrelease)
        else:
            shutil.copy(release, inrelease)

    def write_gates(self, minimums, overrides=()):
        with open(os.path.join(self.gates, "minimums.json"), "w") as handle:
            json.dump({"minimums": minimums}, handle)
        with open(os.path.join(self.gates, "overrides.json"), "w") as handle:
            json.dump({"rowCount": list(overrides)}, handle)

    def patch(self, module, name, value):
        old = getattr(module, name)
        setattr(module, name, value)
        self.addCleanup(setattr, module, name, old)

    def run_build(self, previous=None, cache="cache", log=None, now=None, previous_dates=None):
        site = os.path.join(self.tmp, "site", "v1")
        log = log or helpers_log()
        result = osvfeed.build_releases(site, log, os.path.join(self.tmp, cache), os.path.join(self.tmp, "work"),
                                        previous=previous, releases=[UBU], golden_dir=self.golden,
                                        gates_dir=self.gates, today="2026-11-05", now=now,
                                        previous_dates=previous_dates)
        return site, log, result

    def test_build(self):
        site, log, (releases, sources, failures) = self.run_build()
        self.assertEqual(failures, {})
        entry = releases["ubuntu-24.04"]
        self.assertEqual(entry["rows"], 2)
        with open(os.path.join(site, entry["file"]), "rb") as handle:
            data = handle.read()
        self.assertEqual(netfetch.hashlib.sha256(data).hexdigest(), entry["sha256"])
        body = json.loads(data)
        self.assertEqual(body["pkgs"], {"openssl": [["0", "3.0.13-0ubuntu3.6", 3, ["CVE-2026-0050"], "2026-02-02"]]})
        self.assertEqual(body["kernel"], {"linux-gcp": [["0", "6.8.0-1020.21", 3, 1, "2026-01-10"]]})
        self.assertEqual(sources["osv"], {"Ubuntu": "2026-02-03T04:05:06Z"})
        self.assertEqual(sources["baseline"], {"ubuntu-24.04": "2024-04-25"})
        self.assertEqual(set(sources["archive"]), {"noble", "noble-updates", "noble-security"})
        self.assertTrue(any("InRelease signature OK" in line for line in log.lines))
        self.assertTrue(any("archive versions skipped (unparseable) 1" in line for line in log.lines), log.lines)
        with open(os.path.join(self.tmp, "work", "ubuntu-24.04.rows.json")) as handle:
            work_rows = json.load(handle)["rows"]
        self.assertEqual({r["source"]: r["date"] for r in work_rows},
                         {"openssl": "2026-02-02", "linux-gcp": "2026-01-10"})
        # The zip is not downloaded again while modified_id.csv shows nothing newer.
        _, log2, _ = self.run_build()
        self.assertTrue(any("download skipped" in line for line in log2.lines), log2.lines)
        self.assertTrue(any("all cached" in line for line in log2.lines))

    def test_unsigned_inrelease_fails_only_that_release(self):
        self.write_suite("noble-security", "Package: linux-gcp\nVersion: 6.8.0-1020.21\n", sign=False)
        site, log, (releases, sources, failures) = self.run_build()
        self.assertEqual(releases, {})
        self.assertIn("no valid signature", failures["ubuntu-24.04"])
        self.assertIn("ubuntu-24.04-esm", osvfeed.RELEASE_KEYS)

    def test_valid_until_enforced(self):
        sources = "Package: linux-gcp\nVersion: 6.8.0-1020.21\n"
        self.write_suite("noble-security", sources, extra="Valid-Until: Thu, 12 Nov 2026 15:10:33 UTC\n")
        _, _, (releases, _, failures) = self.run_build(now="2026-11-05T17:10:00Z")
        self.assertEqual(failures, {})
        _, _, (releases, _, failures) = self.run_build(now="2026-11-13T05:10:00Z")
        self.assertEqual(releases, {})
        self.assertIn("noble-security: InRelease expired (Valid-Until 2026-11-12T15:10:33Z", failures["ubuntu-24.04"])
        # No `now` (the snapshot tools): not checked.
        _, _, (_, _, failures) = self.run_build()
        self.assertEqual(failures, {})

    def test_date_must_not_go_backwards(self):
        same = {"noble": "2024-04-25T15:10:33Z"}
        _, _, (_, sources, failures) = self.run_build(previous_dates=same)
        self.assertEqual(failures, {})
        self.assertEqual(sources["archive"]["noble"], "2024-04-25T15:10:33Z")
        newer = {"noble": "2024-04-26T00:00:00Z"}
        _, _, (releases, _, failures) = self.run_build(previous_dates=newer)
        self.assertEqual(releases, {})
        self.assertIn("noble: InRelease Date 2024-04-25T15:10:33Z is older than the 2024-04-26T00:00:00Z",
                      failures["ubuntu-24.04"])

    def test_rows_record_each_ids_severity_rule(self):
        _, _, _ = self.run_build()
        with open(os.path.join(self.tmp, "work", "ubuntu-24.04.rows.json")) as handle:
            rows = json.load(handle)["rows"]
        self.assertEqual({r["source"]: r["rules"] for r in rows},
                         {"openssl": {"CVE-2026-0050": "ubuntu priority"},
                          "linux-gcp": {"CVE-2026-0051": "ubuntu priority"}})

    def test_a_code_bug_is_marked_as_a_bug(self):
        def broken(*args, **kwargs):
            raise KeyError("rows")
        self.patch(osvfeed, "_one_release", broken)
        _, _, (releases, _, failures) = self.run_build()
        self.assertEqual(releases, {})
        self.assertTrue(failures["ubuntu-24.04"].startswith("bug: build: KeyError: 'rows'"))
        self.assertIn("Traceback", failures["ubuntu-24.04"])

    def test_tampered_sources_fails_soft(self):
        path = os.path.join(self.mirror, "dists", "noble", "main", "source", "Sources.xz")
        with open(path, "wb") as handle:
            handle.write(lzma.compress(b"Package: openssl\nVersion: 9.9\n"))
        _, _, (releases, _, failures) = self.run_build()
        self.assertEqual(releases, {})
        self.assertIn("(truncated?)", failures["ubuntu-24.04"])   # size first, then the digest
        self.assertFalse(failures["ubuntu-24.04"].startswith(osvfeed.BUG_PREFIX), "upstream-shaped, not a bug")
        with open(path, "wb") as handle:
            handle.write(b"x" * 100)                                 # same size, other bytes
        _, _, (releases, _, failures) = self.run_build(cache="cache4")
        self.assertIn("does not match its Release file", failures["ubuntu-24.04"])

    def test_unknown_shape_fails_soft(self):
        osv = os.path.join(self.tmp, "osv", "Ubuntu")
        write_zip(os.path.join(osv, "all.zip"), [
            record("UBUNTU-CVE-2026-0060", [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "xx"},
                                             "ranges": [{"type": "GIT", "events": fixed("abc")}]}])])
        with open(os.path.join(osv, "modified_id.csv"), "w") as handle:
            handle.write("2027-01-01T00:00:00Z,UBUNTU-CVE-2026-0060\n")
        _, _, (releases, _, failures) = self.run_build(cache="cache2")
        self.assertEqual(releases, {})
        self.assertIn("unknown range shape", failures["ubuntu-24.04"])

    def test_gates_fail_soft(self):
        self.write_gates({"ubuntu-24.04": 5})
        _, _, (releases, _, failures) = self.run_build()
        self.assertIn("under the floor 5", failures["ubuntu-24.04"])
        self.write_gates({"ubuntu-24.04": 1})
        with open(os.path.join(self.golden, "inv.tsv"), "w") as handle:
            handle.write("openssl\t3.0.13-0ubuntu3.6\n")   # no longer flags: the golden "exact" misses it
        _, _, (releases, _, failures) = self.run_build()
        self.assertIn("missing ['openssl']", failures["ubuntu-24.04"])

    def test_unreachable_osv_fails_soft(self):
        self.patch(netfetch, "OSV_BASE", "file://" + os.path.join(self.tmp, "nowhere"))
        _, _, (releases, _, failures) = self.run_build(cache="cache3")
        self.assertEqual(releases, {})
        self.assertIn("osv Ubuntu", failures["ubuntu-24.04"])

    def test_config_errors_still_raise(self):
        with open(os.path.join(self.gates, "minimums.json"), "w") as handle:
            handle.write("{")
        with self.assertRaises(osvfeed.ConfigError):
            self.run_build()


def helpers_log():
    import build
    return build.Log(echo=False)


if __name__ == "__main__":
    unittest.main()
