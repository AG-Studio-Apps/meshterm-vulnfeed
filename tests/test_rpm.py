"""S5: the EL (rpm) release files. AlmaLinux and RHEL ingest (the merged Red Hat repositories, the summary-prefix and
CVSS severities, module streams, the kernel fold and the binaries dropped), the compact body and its schema, the
fit-to-cap prune, the golden listing parser and the stream rule, and end-to-end build_releases() over file:// zips."""
import collections
import json
import os
import shutil
import tempfile
import unittest

import helpers  # noqa: F401  (puts builder/ on sys.path)
import build
import netfetch
import osvfeed
import rpmver
from feedlib import FILE_CAP, FeedError
from test_osvfeed import CVSS_CRIT, CVSS_HIGH, CVSS_MED, affected, helpers_log, record, write_zip

netfetch.RETRY_DELAY = 0
ALMA = next(r for r in osvfeed.RELEASES if r.key == "alma-9")
RHEL = next(r for r in osvfeed.RELEASES if r.key == "rhel-9")
FX = [{"introduced": "0"}]


def fx(version):
    return FX + [{"fixed": version}]


def alsa(rid, summary, entries, upstream, published="2026-10-01T00:00:00Z"):
    rec = record(rid, entries, upstream=upstream, published=published)
    rec["summary"] = summary
    return rec


def rhsa(rid, summary, entries, upstream, score=CVSS_HIGH, published="2026-10-01T00:00:00Z"):
    rec = record(rid, entries, upstream=upstream, severity=[{"type": "CVSS_V3", "score": score}], published=published)
    rec["summary"] = summary
    return rec


class Config(unittest.TestCase):
    def test_releases(self):
        rpm = [r for r in osvfeed.RELEASES if r.format == "rpm"]
        self.assertEqual([r.key for r in rpm], ["alma-8", "alma-9", "alma-10", "rhel-8", "rhel-9", "rhel-10"])
        self.assertEqual({r.osv_zip for r in rpm}, {"AlmaLinux", "Red Hat"})
        self.assertTrue(all(not r.has_archive for r in rpm))

    def test_rhel_merges_the_main_repositories_only(self):
        for eco in ("Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream",
                    "Red Hat:enterprise_linux:9::crb"):
            self.assertTrue(RHEL.takes(eco), eco)
        for eco in ("Red Hat:enterprise_linux:9::realtime", "Red Hat:rhel_eus:9.6::appstream",
                    "Red Hat:enterprise_linux:8::baseos", "Red Hat:enterprise_linux:9", "AlmaLinux:9",
                    "Red Hat:enterprise_linux:9::baseos\n"):
            self.assertFalse(RHEL.takes(eco), eco)
        rhel10 = next(r for r in osvfeed.RELEASES if r.key == "rhel-10")
        self.assertTrue(rhel10.takes("Red Hat:enterprise_linux:10.2"))
        self.assertTrue(rhel10.takes("Red Hat:enterprise_linux:10::appstream"))
        self.assertFalse(rhel10.takes("Red Hat:enterprise_linux_eus:10.0"))
        self.assertFalse(rhel10.takes("Red Hat:enterprise_linux:10::fastdatapath"))
        self.assertTrue(ALMA.takes("AlmaLinux:9") and not ALMA.takes("AlmaLinux:8"))

    def test_summary_parsing(self):
        self.assertEqual(osvfeed.module_streams("Important: php:8.1 security update"), ["php:8.1"])
        self.assertEqual(osvfeed.module_streams("Red Hat Security Advisory: virt:rhel and virt-devel:rhel security"),
                         ["virt-devel:rhel", "virt:rhel"])
        self.assertEqual(osvfeed.module_streams("Moderate: 389-ds:1.4 security update"), ["389-ds:1.4"])
        self.assertEqual(osvfeed.module_streams("Important: kernel security update"), [])
        self.assertEqual(osvfeed.module_streams(None), [])
        self.assertEqual(osvfeed.alma_prefix_band("Critical: firefox security update"), 4)
        self.assertEqual(osvfeed.alma_prefix_band("Important: kernel security update"), 3)
        self.assertEqual(osvfeed.alma_prefix_band("Moderate: x"), 2)
        self.assertIsNone(osvfeed.alma_prefix_band("idm:DL1 bug fix update"))
        self.assertIsNone(osvfeed.alma_prefix_band("container-tools bug fix update"))


class IngestAndResolve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-rpm-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_release(self, release, records):
        path = os.path.join(self.tmp, "all.zip")
        write_zip(path, records)
        cands, info, stats, shapes, _ = osvfeed.ingest(path, [release], helpers_log())
        counters, decisions = collections.Counter(), collections.Counter()
        rows, _, dropped = osvfeed.resolve_rpm(release, cands[release.key], info, counters, decisions)
        return rows, counters, decisions, stats, shapes, dropped

    def test_alma_prefix_severity_and_binaries(self):
        rows, counters, decisions, stats, shapes, _ = self.run_release(ALMA, [
            alsa("ALSA-2026:1001", "Important: openssl security update", [
                affected("AlmaLinux:9", "openssl", fx("1:3.5.8-2.el9_8")),
                affected("AlmaLinux:9", "openssl-libs", fx("1:3.5.8-2.el9_8")),
                affected("AlmaLinux:9", "openssl-debuginfo", fx("1:3.5.8-2.el9_8")),
                affected("AlmaLinux:8", "openssl", fx("1:1.1.1k-14.el8_10"))], ["CVE-2026-1001", "CVE-2026-1002"]),
            alsa("ALSA-2026:1002", "Moderate: zlib security update", [
                affected("AlmaLinux:9", "zlib", fx("1.2.11-41.el9_8"))], ["CVE-2026-1003"]),
            alsa("ALSA-2026:1003", "Critical: NetworkManager security update", [
                affected("AlmaLinux:9", "NetworkManager", fx("1:1.48.10-5.el9_8"))], ["CVE-2026-1004"]),
            alsa("ALBA-2026:1004", "glibc bug fix update", [
                affected("AlmaLinux:9", "glibc", fx("2.34-283.el9_8"))], []),
        ])
        self.assertEqual(shapes, [])
        self.assertEqual(sorted((r["source"], r["fixed"], r["severity"]) for r in rows),
                         [("NetworkManager", "1:1.48.10-5.el9_8", 4), ("openssl", "1:3.5.8-2.el9_8", 3),
                          ("openssl-libs", "1:3.5.8-2.el9_8", 3)])
        self.assertEqual(decisions, {"alma summary prefix": 6})
        self.assertEqual(counters["below High (dropped)"], 1)
        self.assertEqual(stats["alma-9: debuginfo / debugsource (dropped)"], 1)
        self.assertEqual(stats["alma-9: no CVE id (dropped)"], 1)
        body = osvfeed.release_body(ALMA, rows)
        self.assertEqual((body["format"], body["keyedBy"]), ("rpm", "binary"))
        self.assertEqual(body["ids"], ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1004"])
        self.assertEqual(body["fixes"], [["0", "1:1.48.10-5.el9_8", 4, [2], []],
                                         ["0", "1:3.5.8-2.el9_8", 3, [0, 1], []]], "sorted by fixed EVR")
        self.assertEqual(body["pkgs"], {"NetworkManager": [0], "openssl": [1], "openssl-libs": [1]})
        osvfeed.check_release_body(json.loads(json.dumps(body)), "alma-9",
                                   {"format": "rpm", "file": "x", "rows": 3})

    def test_rhel_cvss_merged_repositories_and_kernel(self):
        rows, counters, decisions, stats, _, _ = self.run_release(RHEL, [
            rhsa("RHSA-2026:2001", "Red Hat Security Advisory: kernel security update", [
                affected("Red Hat:enterprise_linux:9::baseos", "kernel-core", fx("0:5.14.0-611.5.1.el9_8")),
                affected("Red Hat:enterprise_linux:9::baseos", "kernel", fx("0:5.14.0-611.5.1.el9_8")),
                affected("Red Hat:enterprise_linux:9::baseos", "kernel-modules", fx("0:5.14.0-611.5.1.el9_8")),
                affected("Red Hat:enterprise_linux:9::appstream", "kernel-headers", fx("0:5.14.0-611.5.1.el9_8")),
                affected("Red Hat:enterprise_linux:9::realtime", "kernel-rt-core", fx("0:5.14.0-611.5.1.el9_8"))],
                ["CVE-2026-2001", "CVE-2026-2002"], score=CVSS_CRIT),
            rhsa("RHSA-2026:2002", "Red Hat Security Advisory: curl security update", [
                affected("Red Hat:enterprise_linux:9::baseos", "curl", fx("0:7.76.1-40.el9_8.8")),
                affected("Red Hat:enterprise_linux:9::appstream", "curl", fx("0:7.76.1-40.el9_8.8")),
                affected("Red Hat:enterprise_linux:9::crb", "libcurl-devel", fx("0:7.76.1-40.el9_8.8")),
                affected("Red Hat:rhel_eus:9.6::baseos", "curl", fx("0:7.76.1-31.el9_6.4"))], ["CVE-2026-2003"]),
            rhsa("RHSA-2026:2003", "Red Hat Security Advisory: less security update", [
                affected("Red Hat:enterprise_linux:9::baseos", "less", fx("0:590-6.el9_8"))], ["CVE-2026-2004"],
                score=CVSS_MED),
        ])
        self.assertEqual(sorted((r["source"], r["kernel"]) for r in rows),
                         [("curl", False), ("kernel-core", True), ("libcurl-devel", False)])
        self.assertEqual(stats["rhel-9: kernel binary other than kernel-core (dropped)"], 3)
        self.assertEqual(decisions["cvss"], 5)
        body = osvfeed.release_body(RHEL, rows)
        self.assertEqual(body["kernel"], {"kernel-core": [["0", "0:5.14.0-611.5.1.el9_8", 4, 2, "2026-10-01"]]})
        self.assertNotIn("kernel-core", body["pkgs"])
        osvfeed.check_release_body(json.loads(json.dumps(body)), "rhel-9", {"format": "rpm", "file": "x", "rows": 3})

    def test_module_streams_merged_per_fix(self):
        rows, counters, _, stats, _, _ = self.run_release(ALMA, [
            alsa("ALSA-2026:3001", "Important: php:8.2 security update", [
                affected("AlmaLinux:9", "php-cli", fx("8.2.33-1.module_el9.8.0+303+1bef6c12"))], ["CVE-2026-3001"]),
            alsa("ALSA-2026:3002", "Important: php:8.2 and php-pecl:8.2 security update", [
                affected("AlmaLinux:9", "php-cli", fx("8.2.33-1.module_el9.8.0+303+1bef6c12"))], ["CVE-2026-3002"]),
            alsa("ALSA-2026:3003", "Important: php:8.3 security update", [
                affected("AlmaLinux:9", "php-cli", fx("8.3.36-1.module_el9.8.0+330+fdc30075"))], ["CVE-2026-3003"]),
            alsa("ALSA-2026:3004", "Important: container-tools security update", [
                affected("AlmaLinux:9", "podman", fx("4:5.2.2-1.module_el9.8.0+1+aaaa"))], ["CVE-2026-3004"]),
            alsa("ALSA-2026:3005", "Important: php security update", [
                affected("AlmaLinux:9", "php-cli", fx("8.0.30-8.el9_8.1"))], ["CVE-2026-3005"]),
        ])
        by_fix = {r["fixed"]: r for r in rows}
        self.assertEqual(by_fix["8.2.33-1.module_el9.8.0+303+1bef6c12"]["streams"], ["php-pecl:8.2", "php:8.2"])
        self.assertEqual(by_fix["8.2.33-1.module_el9.8.0+303+1bef6c12"]["ids"], ["CVE-2026-3001", "CVE-2026-3002"])
        self.assertEqual(by_fix["8.3.36-1.module_el9.8.0+330+fdc30075"]["streams"], ["php:8.3"])
        self.assertEqual(by_fix["4:5.2.2-1.module_el9.8.0+1+aaaa"]["streams"], [])
        self.assertEqual(by_fix["8.0.30-8.el9_8.1"]["streams"], [], "a plain build carries no stream")
        self.assertEqual(stats["alma-9: modular fix with no stream in its summary"], 1)
        self.assertEqual(counters["modular rows"], 3)
        body = osvfeed.release_body(ALMA, rows)
        osvfeed.check_release_body(json.loads(json.dumps(body)), "alma-9", {"format": "rpm", "file": "x", "rows": 4})

    def test_bad_versions_rejected(self):
        rows, counters, _, _, _, _ = self.run_release(ALMA, [
            alsa("ALSA-2026:4001", "Important: a", [affected("AlmaLinux:9", "a", fx("1.0-1-2"))], ["CVE-2026-4001"]),
            alsa("ALSA-2026:4002", "Important: b", [affected("AlmaLinux:9", "b", fx("2026-08-16"))], ["CVE-2026-4002"]),
            alsa("ALSA-2026:4003", "Important: c", [affected("AlmaLinux:9", "c", fx("1.0-1.el9"))], ["CVE-2026-4003"]),
        ])
        self.assertEqual([r["source"] for r in rows], ["c"])
        self.assertEqual(counters["rejected"], 2)
        self.assertEqual(counters["rejected: date-shaped"], 1)
        self.assertEqual(counters["rejected: fixed not an rpm EVR"], 1)


class Body(unittest.TestCase):
    ENTRY = {"format": "rpm", "file": "r/alma-9-x.json", "rows": 4}

    def body(self):
        return {"release": "alma-9", "format": "rpm", "keyedBy": "binary",
                "ids": ["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003"],
                "fixes": [["0", "0:3.5.8-2.el9_8", 3, [0, 1], []],
                          ["0", "8.2.33-1.module_el9.8.0+303+1bef6c12", 4, [2], ["php:8.2"]]],
                "pkgs": {"openssl": [0], "openssl-libs": [0], "php-cli": [1]},
                "kernel": {"kernel-core": [["0", "5.14.0-611.5.1.el9_8", 4, 7, "2026-10-01"]]}}

    def check(self, body, entry=None, key="alma-9"):
        osvfeed.check_release_body(json.loads(json.dumps(body)), key, entry or self.ENTRY)

    def test_accepts(self):
        self.check(self.body())

    def test_refusals(self):
        def bad(change, why, entry=None, key="alma-9"):
            body = self.body()
            change(body)
            with self.subTest(why=why), self.assertRaisesRegex(FeedError, why):
                self.check(body, entry, key)
        bad(lambda b: b.update(keyedBy="source"), "do not match")
        bad(lambda b: b.pop("ids"), "keys must be")
        bad(lambda b: None, "keys must be", entry=dict(self.ENTRY, format="dpkg"))
        bad(lambda b: b.update(release="debian-12"), "do not match", key="debian-12")   # an rpm body for dpkg
        bad(lambda b: b["ids"].reverse(), "bad ids table")
        bad(lambda b: b["ids"].__setitem__(0, "RHSA-2026:1"), "bad ids table")
        bad(lambda b: b["ids"].append("CVE-2026-19999"), "an id no fix names")
        bad(lambda b: b["fixes"].reverse(), "not sorted")
        bad(lambda b: b["fixes"][0].__setitem__(1, "1.0-1-2"), "bad version")
        bad(lambda b: b["fixes"][0].__setitem__(2, 2), "not High or Critical")
        bad(lambda b: b["fixes"][0].__setitem__(3, [1, 0]), "bad id indexes")
        bad(lambda b: b["fixes"][0].__setitem__(3, [7]), "bad id indexes")
        bad(lambda b: b["fixes"][0].__setitem__(4, ["php:8.2"]), "bad streams")      # streams on a plain build
        bad(lambda b: b["fixes"][1].__setitem__(4, ["php 8.2"]), "bad streams")
        bad(lambda b: b["pkgs"].update({"php-cli": [5]}), "bad fix indexes")
        bad(lambda b: b["pkgs"].update({"php-cli": []}), "bad fix indexes")
        bad(lambda b: b["pkgs"].pop("php-cli"), "a fix no binary names")
        bad(lambda b: b["pkgs"].update({"kernel-core": [0]}), "bad pkgs binary")
        bad(lambda b: b["pkgs"].update({"bad name": [0]}), "bad pkgs binary")
        bad(lambda b: b["kernel"].update({"kernel": b["kernel"].pop("kernel-core")}), "bad kernel source")
        bad(lambda b: None, "4 rows, the manifest says 5", entry=dict(self.ENTRY, rows=5))
        body = self.body()
        body["pkgs"]["NetworkManager"] = [0]
        self.check(body, dict(self.ENTRY, rows=5))

    def test_prune_superseded(self):
        rows = [{"source": "firefox", "introduced": "0", "fixed": f"140.{n}.0-1.el9_8", "severity": 3,
                 "ids": [f"CVE-2026-{1000 + n}"], "kernel": False, "streams": []} for n in range(1, 8)]
        rows.append({"source": "kernel-core", "introduced": "0", "fixed": "5.14.0-1.el9", "severity": 3,
                     "ids": ["CVE-2026-1"], "kernel": True})
        kept, gone = osvfeed.prune_superseded(rows, 3)
        self.assertEqual(gone, 4)
        self.assertEqual(sorted(r["fixed"] for r in kept if not r["kernel"]),
                         ["140.5.0-1.el9_8", "140.6.0-1.el9_8", "140.7.0-1.el9_8"])
        self.assertTrue(any(r["kernel"] for r in kept), "kernel rows are never pruned")


LISTING = """# a comment
openssl-libs\t1:3.5.5-2.el9_8\tx86_64\topenssl-3.5.5-2.el9_8.src.rpm\t(none)
openssl\t1:3.5.5-2.el9_8\tx86_64\topenssl-3.5.5-2.el9_8.src.rpm\t(none)
glibc\t0:2.34-266.el9_8\ti686\tglibc-2.34-266.el9_8.src.rpm\t(none)
glibc\t0:2.34-270.el9_8\tx86_64\tglibc-2.34-270.el9_8.src.rpm\t(none)
gpg-pubkey\t0:fd431d51-4ae0493b\t(none)\t(none)\t(none)
php-cli\t0:8.2.31-1.module_el9.8.0+254+5708f44c\tx86_64\tphp-8.2.31-1.module_el9.8.0+254+5708f44c.src.rpm\tphp:8.2:9080020260601000000:5708f44c
NetworkManager\t1:1.48.10-4.el9_8\tx86_64\tNetworkManager-1.48.10-4.el9_8.src.rpm\t(none)
"""


class Golden(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-rpm-golden-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.path = os.path.join(self.tmp, "l.rpm.tsv")
        with open(self.path, "w") as handle:
            handle.write(LISTING)

    def test_listing_parser(self):
        inv = osvfeed.read_rpm_inventory(self.path)
        self.assertEqual(inv["glibc"], ("0:2.34-270.el9_8", "glibc", None), "the highest EVR of a name")
        self.assertEqual(inv["php-cli"][2], "php:8.2:9080020260601000000:5708f44c")
        self.assertEqual(inv["NetworkManager"][1], "NetworkManager")
        self.assertNotIn("gpg-pubkey", inv)
        with open(self.path, "w") as handle:
            handle.write("openssl\t1:3.5.5-2.el9_8\tx86_64\n")
        with self.assertRaises(FeedError):
            osvfeed.read_rpm_inventory(self.path)
        self.assertEqual(osvfeed.source_rpm_name("openssl-3.5.5-2.el9_8.src.rpm"), "openssl")
        self.assertEqual(osvfeed.source_rpm_name("python3.9-3.9.25-7.el9_8.src.rpm"), "python3.9")
        self.assertIsNone(osvfeed.source_rpm_name("(none)"))
        self.assertEqual(osvfeed.label_stream("php:8.2:9080020260601000000:5708f44c"), "php:8.2")
        self.assertIsNone(osvfeed.label_stream(None))

    def test_stream_rule(self):
        ok = osvfeed.rpm_stream_ok
        host = "0:8.2.31-1.module_el9.8.0+254+5708f44c"
        label = "php:8.2:9080020260601000000:5708f44c"
        self.assertTrue(ok("8.2.33-1.module_el9.8.0+303+1bef6c12", ["php:8.2"], host, label))
        self.assertFalse(ok("8.3.36-1.module_el9.8.0+330+fdc30075", ["php:8.3"], host, label), "another stream")
        self.assertFalse(ok("8.1.32-1.module_el9.8.0+326+528679fc.alma.1", ["php:8.1"], host, label))
        self.assertFalse(ok("8.0.30-8.el9_8.1", [], host, label), "a plain row never meets a modular build")
        self.assertFalse(ok("8.2.33-1.module_el9.8.0+303+1bef6c12", ["php:8.2"], "8.0.30-6.el9_8", None),
                         "a modular row never meets a plain build")
        # No label (or no stream on the row): the upstream major.minor must agree.
        self.assertTrue(ok("8.2.33-1.module_el9.8.0+303+1bef6c12", [], host, None))
        self.assertFalse(ok("8.3.36-1.module_el9.8.0+330+fdc30075", [], host, label))
        self.assertTrue(ok("8.0.30-8.el9_8.1", [], "8.0.30-6.el9_8", None))

    def test_hits_grouped_by_source_rpm(self):
        inv = osvfeed.read_rpm_inventory(self.path)

        def row(source, fixed, streams=(), date="2026-10-01", kernel=False):
            return {"source": source, "introduced": "0", "fixed": fixed, "streams": list(streams), "date": date,
                    "kernel": kernel}
        rows = [row("openssl-libs", "1:3.5.8-2.el9_8"), row("openssl", "1:3.5.8-2.el9_8"),
                row("glibc", "2.34-270.el9_8"),                                   # the highest EVR is not below it
                row("php-cli", "8.2.33-1.module_el9.8.0+303+1bef6c12", ["php:8.2"]),
                row("php-cli", "8.3.36-1.module_el9.8.0+330+fdc30075", ["php:8.3"]),
                row("NetworkManager", "1:1.48.10-5.el9_8", date="2026-11-06"),     # after the capture
                row("kernel-core", "5.14.0-9.el9", kernel=True)]
        hits = osvfeed.rpm_hits(rows, inv, "2026-11-05")
        self.assertEqual(hits, {"openssl": ["1:3.5.8-2.el9_8", "1:3.5.8-2.el9_8"],
                                "php": ["8.2.33-1.module_el9.8.0+303+1bef6c12"]})

    def test_real_fixtures(self):
        cases = [c for c in osvfeed.golden_cases() if osvfeed.FORMAT_OF[c["release"]] == "rpm"]
        self.assertEqual(len(cases), 6)
        for case in cases:
            path = os.path.join(osvfeed.GOLDEN_DIR, case["fixture"])
            self.assertLess(os.path.getsize(path), 32 * 1024)
            with open(path) as handle:
                header = handle.readline()
            if case["fixture"].startswith("synthetic-"):
                self.assertTrue(header.startswith("# SYNTHETIC (no real host, no image)"))
            else:
                self.assertRegex(header, r"^# Stock \S+ \(\S+@sha256:[0-9a-f]{64}, image id [0-9a-f]{12}, "
                                         r"/etc/os-release (almalinux|rocky) 9\.\d+\)")
            inv = osvfeed.read_rpm_inventory(path)
            self.assertTrue(inv)
            self.assertNotIn("archive", case)
        stock = next(c for c in cases if c["fixture"] == "almalinux-9-stock.rpm.tsv")
        self.assertEqual(stock.get("exact"), [], "the EL false-positive gate")


class EndToEnd(unittest.TestCase):
    """build_releases() for alma-9 and rhel-9 over file:// OSV zips: no archive, no baseline, no gpg."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-rpm-e2e-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.write_osv("AlmaLinux", [
            alsa("ALSA-2026:1001", "Important: openssl security update", [
                affected("AlmaLinux:9", "openssl-libs", fx("1:3.5.8-2.el9_8"))], ["CVE-2026-1001"]),
            alsa("ALSA-2026:1002", "Important: kernel security update", [
                affected("AlmaLinux:9", "kernel-core", fx("5.14.0-611.5.1.el9_8"))], ["CVE-2026-1002"]),
        ], "2026-11-05T09:30:02Z")
        self.write_osv("Red Hat", [
            rhsa("RHSA-2026:2001", "Red Hat Security Advisory: openssl security update", [
                affected("Red Hat:enterprise_linux:9::baseos", "openssl-libs", fx("1:3.5.8-2.el9_8"))],
                ["CVE-2026-1001"]),
        ], "2026-11-05T10:00:00Z")
        self.golden = os.path.join(self.tmp, "golden")
        os.makedirs(self.golden)
        with open(os.path.join(self.golden, "inv.rpm.tsv"), "w") as handle:
            handle.write("openssl-libs\t1:3.5.5-2.el9_8\tx86_64\topenssl-3.5.5-2.el9_8.src.rpm\t(none)\n")
        with open(os.path.join(self.golden, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.rpm.tsv", "release": "alma-9", "capture": "2026-11-05",
                                  "atLeast": ["openssl"]},
                                 {"fixture": "inv.rpm.tsv", "release": "rhel-9", "capture": "2026-11-05",
                                  "exact": ["openssl"]}]}, handle)
        self.gates = os.path.join(self.tmp, "gates")
        os.makedirs(self.gates)
        with open(os.path.join(self.gates, "minimums.json"), "w") as handle:
            json.dump({"minimums": {"alma-9": 1, "rhel-9": 1}}, handle)
        with open(os.path.join(self.gates, "overrides.json"), "w") as handle:
            json.dump({"rowCount": []}, handle)
        old = netfetch.OSV_BASE
        netfetch.OSV_BASE = "file://" + os.path.join(self.tmp, "osv")
        self.addCleanup(setattr, netfetch, "OSV_BASE", old)

    def write_osv(self, zip_name, records, newest):
        directory = os.path.join(self.tmp, "osv", zip_name)
        os.makedirs(directory, exist_ok=True)
        write_zip(os.path.join(directory, "all.zip"), records)
        with open(os.path.join(directory, "modified_id.csv"), "w") as handle:
            handle.write(f"{newest},X\n")

    def run_build(self, cache="cache"):
        site = os.path.join(self.tmp, "site", "v1")
        result = osvfeed.build_releases(site, helpers_log(), os.path.join(self.tmp, cache),
                                        os.path.join(self.tmp, "work"), releases=[ALMA, RHEL],
                                        golden_dir=self.golden, gates_dir=self.gates, today="2026-11-05")
        return site, result

    def test_build(self):
        site, (releases, sources, failures) = self.run_build()
        self.assertEqual(failures, {})
        self.assertEqual({k: (v["format"], v["rows"]) for k, v in releases.items()},
                         {"alma-9": ("rpm", 2), "rhel-9": ("rpm", 1)})
        with open(os.path.join(site, releases["alma-9"]["file"]), "rb") as handle:
            body = json.loads(handle.read())
        self.assertEqual(body, {"release": "alma-9", "format": "rpm", "keyedBy": "binary", "ids": ["CVE-2026-1001"],
                                "fixes": [["0", "1:3.5.8-2.el9_8", 3, [0], []]], "pkgs": {"openssl-libs": [0]},
                                "kernel": {"kernel-core": [["0", "5.14.0-611.5.1.el9_8", 3, 1, "2026-10-01"]]}})
        self.assertEqual(sources["osv"], {"AlmaLinux": "2026-01-11T00:00:00Z", "Red Hat": "2026-01-11T00:00:00Z"})
        build.check_sources(sources, releases)

    def test_one_zip_failing_keeps_the_other(self):
        self.write_osv("Red Hat", [rhsa("RHSA-2026:2001", "x", [
            {"package": {"ecosystem": "Red Hat:enterprise_linux:9::baseos", "name": "openssl-libs"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1"}]}]}],
            ["CVE-2026-1001"])], "2027-01-01T00:00:00Z")
        _, (releases, _, failures) = self.run_build(cache="cache2")
        self.assertEqual(set(releases), {"alma-9"})
        self.assertIn("unknown range shape", failures["rhel-9"])

    def test_fit_to_cap(self):
        # Many superseded fixes of one binary, with long id lists: over FILE_CAP until pruned.
        recs = [alsa(f"ALSA-2026:{n}", "Important: firefox security update", [
            affected("AlmaLinux:9", name, fx(f"140.{n}.0-1.el9_8")) for name in ("firefox", "firefox-x11")],
            [f"CVE-2026-{n * 1000 + i:06d}" for i in range(150)]) for n in range(1, 400)]
        self.write_osv("AlmaLinux", recs, "2027-02-01T00:00:00Z")
        golden, gates = os.path.join(self.tmp, "golden3"), os.path.join(self.tmp, "gates3")
        os.makedirs(golden)
        os.makedirs(gates)
        with open(os.path.join(golden, "expected.json"), "w") as handle:
            json.dump({"cases": []}, handle)
        with open(os.path.join(gates, "minimums.json"), "w") as handle:
            json.dump({"minimums": {"alma-9": 1}}, handle)
        with open(os.path.join(gates, "overrides.json"), "w") as handle:
            json.dump({"rowCount": []}, handle)
        log = helpers_log()
        site = os.path.join(self.tmp, "site3", "v1")
        releases, _, failures = osvfeed.build_releases(site, log, os.path.join(self.tmp, "cache3"),
                                                       os.path.join(self.tmp, "work3"), releases=[ALMA],
                                                       golden_dir=golden, gates_dir=gates, today="2026-11-05")
        if failures:
            self.fail(failures)
        self.assertLessEqual(releases["alma-9"]["bytes"], FILE_CAP)
        self.assertTrue(any("over the" in line and "cap: kept the newest" in line for line in log.lines))


if __name__ == "__main__":
    unittest.main()
