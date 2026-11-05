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
             "ids": ["CVE-2026-4"], "kernel": False, "date": "2026-09-01"},
        ]
        body = osvfeed.release_body(UBU, rows)
        self.assertEqual(body["kernel"], {"linux-aws-6.8": [["0", "6.8.0-1038.40~22.04.1", 4, 1, "2026-10-01"],
                                                               ["0", "6.8.0-1040.42~22.04.1", 3, 2, "2026-10-30"]]})
        self.assertEqual(body["pkgs"], {"linuxptp": [["0", "4.0-1ubuntu0.1", 3, ["CVE-2026-4"]]]})
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
    def row(self, source, fixed, date="2026-10-01", source_kind="advisory", modified="2026-10-02", intro="0"):
        return {"source": source, "introduced": intro, "fixed": fixed, "severity": 3, "ids": ["CVE-2026-1"],
                "kernel": False, "date": date, "dateSource": source_kind, "modified": modified}

    def test_capture_date_filter(self):
        inventory = {"apt": "2.6.1", "glibc": "2.36-9+deb12u10", "curl": "7.88.1-10+deb12u5"}
        rows = [self.row("apt", "2.6.2", date="2026-11-04"),
                self.row("glibc", "2.36-9+deb12u14", date="2026-11-06"),          # after capture: not counted
                self.row("curl", "7.88.1-10+deb12u4")]                              # installed is newer
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05"), {"apt": ["2.6.2"]})

    def test_archive_at_capture_keeps_fixtures_frozen(self):
        # An old CVE whose fix OSV records after the capture: dated 2025, but not in the archive at capture.
        inventory = {"apt": "2.6.1", "curl": "7.88.1-10+deb12u5"}
        rows = [self.row("apt", "2.6.2", date="2026-11-04"),
                self.row("curl", "7.88.1-10+deb12u6", date="2025-01-01", source_kind="record")]
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05"),
                         {"apt": ["2.6.2"], "curl": ["7.88.1-10+deb12u6"]})
        at_capture = {"apt": "2.6.2", "curl": "7.88.1-10+deb12u5"}
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05", at_capture), {"apt": ["2.6.2"]})
        self.assertEqual(osvfeed.golden_hits(rows, inventory, "2026-11-05", {"curl": "9"}),
                         {"curl": ["7.88.1-10+deb12u6"]})

    def test_introduced_respected(self):
        rows = [self.row("x", "2.0-3", intro="2.0-1")]
        self.assertEqual(osvfeed.golden_hits(rows, {"x": "1.9-1"}, "2026-11-05"), {})
        self.assertEqual(osvfeed.golden_hits(rows, {"x": "2.0-2"}, "2026-11-05"), {"x": ["2.0-3"]})

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
        with open(os.path.join(directory, "expected.json")) as handle:
            spec = json.load(handle)
        self.assertEqual(len(spec["cases"]), 3)
        for case in spec["cases"]:
            path = os.path.join(directory, case["fixture"])
            self.assertLess(os.path.getsize(path), 64 * 1024, path)
            self.assertTrue(osvfeed.read_inventory(path))
        stock = osvfeed.read_inventory(os.path.join(directory, "debian-12-stock.tsv"))
        self.assertEqual(stock["apt"], "2.6.1")

    def test_check_golden_reports_misses(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with open(os.path.join(tmp, "inv.tsv"), "w") as handle:
            handle.write("apt\t2.6.1\nsed\t4.9-1\n")
        with open(os.path.join(tmp, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.tsv", "release": "debian-12", "capture": "2026-11-05",
                                  "atLeast": ["apt", "sed"]}]}, handle)
        log = helpers_log()
        osvfeed.check_golden({"debian-12": [self.row("apt", "2.6.2"), self.row("sed", "4.9-1+deb12u1")]}, log, tmp)
        with self.assertRaisesRegex(FeedError, "missing \\['sed'\\]"):
            osvfeed.check_golden({"debian-12": [self.row("apt", "2.6.2")]}, log, tmp)
        with open(os.path.join(tmp, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.tsv", "release": "debian-12", "capture": "2026-11-05",
                                  "exact": []}]}, handle)
        with self.assertRaisesRegex(FeedError, "expected exactly"):
            osvfeed.check_golden({"debian-12": [self.row("apt", "2.6.2")]}, log, tmp)


class RowSwing(unittest.TestCase):
    def entry(self, rows):
        return {"format": "dpkg", "file": "r/x-0000000000000000.json", "sha256": "0" * 64, "bytes": 1, "rows": rows}

    def test_first_build_allowed(self):
        log = helpers_log()
        osvfeed.check_row_swing({"debian-12": self.entry(500)}, None, log)
        self.assertIn("first build allowed", log.lines[-1])

    def test_swing_limits(self):
        log = helpers_log()
        osvfeed.check_row_swing({"debian-12": self.entry(129)}, {"debian-12": self.entry(100)}, log)
        osvfeed.check_row_swing({"debian-12": self.entry(1290)}, {"debian-12": self.entry(1000)}, log)
        with self.assertRaisesRegex(FeedError, "debian-12 1000 -> 1301"):
            osvfeed.check_row_swing({"debian-12": self.entry(1301)}, {"debian-12": self.entry(1000)}, log)
        with self.assertRaisesRegex(FeedError, "699"):
            osvfeed.check_row_swing({"debian-12": self.entry(699)}, {"debian-12": self.entry(1000)}, log)
        # Small files: the floor allows +-25 rows.
        osvfeed.check_row_swing({"ubuntu-26.10": self.entry(30)}, {"ubuntu-26.10": self.entry(6)}, log)
        with self.assertRaisesRegex(FeedError, "missing since the previous build"):
            osvfeed.check_row_swing({}, {"debian-12": self.entry(10)}, log)


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


class EndToEnd(unittest.TestCase):
    """build_releases() over file:// mirrors: fake OSV zip + modified_id.csv, fake Release + Sources.xz."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-e2e-")
        self.addCleanup(shutil.rmtree, self.tmp)
        mirror = os.path.join(self.tmp, "mirror")
        osv = os.path.join(self.tmp, "osv", "Ubuntu")
        os.makedirs(osv)
        for suite, sources in (("noble", "Package: openssl\nVersion: 3.0.13-0ubuntu3\n"),
                               ("noble-updates", "Package: openssl\nVersion: 3.0.13-0ubuntu3.6\n"),
                               ("noble-security", "Package: linux-gcp\nVersion: 6.8.0-1020.21\n")):
            directory = os.path.join(mirror, "dists", suite, "main", "source")
            os.makedirs(directory)
            data = lzma.compress(sources.encode())
            with open(os.path.join(directory, "Sources.xz"), "wb") as handle:
                handle.write(data)
            digest = netfetch.hashlib.sha256(data).hexdigest()
            with open(os.path.join(mirror, "dists", suite, "Release"), "w") as handle:
                handle.write(f"Suite: {suite}\nDate: Thu, 25 Apr 2024 15:10:33 UTC\nSHA256:\n"
                             f" {digest} {len(data)} main/source/Sources.xz\n")
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
        with open(os.path.join(self.golden, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.tsv", "release": "ubuntu-24.04", "capture": "2026-11-05",
                                  "exact": ["openssl"]}]}, handle)
        self.patch(osvfeed, "UBUNTU_MIRROR", "file://" + mirror)
        self.patch(netfetch, "OSV_BASE", "file://" + os.path.join(self.tmp, "osv"))

    def patch(self, module, name, value):
        old = getattr(module, name)
        setattr(module, name, value)
        self.addCleanup(setattr, module, name, old)

    def test_build(self):
        site = os.path.join(self.tmp, "site", "v1")
        cache, work = os.path.join(self.tmp, "cache"), os.path.join(self.tmp, "work")
        log = helpers_log()
        releases, sources = osvfeed.build_releases(site, log, cache, work, releases=[UBU],
                                                   golden_dir=self.golden)
        entry = releases["ubuntu-24.04"]
        self.assertEqual(entry["rows"], 2)
        with open(os.path.join(site, entry["file"]), "rb") as handle:
            data = handle.read()
        self.assertEqual(netfetch.hashlib.sha256(data).hexdigest(), entry["sha256"])
        self.assertTrue(entry["file"].startswith("r/ubuntu-24.04-") and entry["file"].endswith(".json"))
        body = json.loads(data)
        self.assertEqual(body["pkgs"], {"openssl": [["0", "3.0.13-0ubuntu3.6", 3, ["CVE-2026-0050"]]]})
        self.assertEqual(body["kernel"], {"linux-gcp": [["0", "6.8.0-1020.21", 3, 1, "2026-01-10"]]})
        self.assertEqual(sources["osv"], {"Ubuntu": "2026-02-03T04:05:06Z"})
        self.assertEqual(sources["baseline"], {"ubuntu-24.04": "2024-04-25"})
        self.assertEqual(set(sources["archive"]), {"noble", "noble-updates", "noble-security"})
        with open(os.path.join(work, "ubuntu-24.04.rows.json")) as handle:
            work_rows = json.load(handle)["rows"]
        self.assertEqual({r["source"]: r["date"] for r in work_rows},
                         {"openssl": "2026-02-02", "linux-gcp": "2026-01-10"})
        self.assertTrue(any("unpublished: archive below fixed 1" in line for line in log.lines))
        # The zip is not downloaded again while modified_id.csv shows nothing newer.
        log2 = helpers_log()
        osvfeed.build_releases(site, log2, cache, work, releases=[UBU], golden_dir=self.golden)
        self.assertTrue(any("download skipped" in line for line in log2.lines), log2.lines)
        self.assertTrue(any("all cached" in line for line in log2.lines))

    def test_unknown_shape_fails_closed(self):
        osv = os.path.join(self.tmp, "osv", "Ubuntu")
        write_zip(os.path.join(osv, "all.zip"), [
            record("UBUNTU-CVE-2026-0060", [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "x"},
                                             "ranges": [{"type": "GIT", "events": fixed("abc")}]}])])
        with open(os.path.join(osv, "modified_id.csv"), "w") as handle:
            handle.write("2027-01-01T00:00:00Z,UBUNTU-CVE-2026-0060\n")
        with self.assertRaisesRegex(FeedError, "unknown range shapes"):
            osvfeed.build_releases(os.path.join(self.tmp, "site", "v1"), helpers_log(),
                                   os.path.join(self.tmp, "cache2"), os.path.join(self.tmp, "work"),
                                   releases=[UBU], golden_dir=self.golden)


def helpers_log():
    import build
    return build.Log(echo=False)


if __name__ == "__main__":
    unittest.main()
