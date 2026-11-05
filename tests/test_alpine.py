"""S4: the Alpine (apk) release files. The range rule, version rejects, severity, the kernel fold, the body
schema, the golden listing parser and matcher, and one end-to-end build_releases() over a file:// OSV zip."""
import collections
import json
import os
import shutil
import tempfile
import unittest

import helpers
import build
import netfetch
import osvfeed
from feedlib import FeedError
from test_osvfeed import CVSS_CRIT, CVSS_HIGH, CVSS_MED, affected, helpers_log, record, write_zip

netfetch.RETRY_DELAY = 0
ALP = osvfeed.Release("alpine-3.22", "alpine", "Alpine:v3.22", None)
ECO = "Alpine:v3.22"


def entry(*events):
    return {"ranges": [{"type": "ECOSYSTEM", "events": [dict([e]) for e in events]}]}


class RangeRule(unittest.TestCase):
    def pairs(self, *events):
        counters = collections.Counter()
        return osvfeed.apk_range_pairs(entry(*events), counters), counters

    def test_single_and_introduced_kept(self):
        self.assertEqual(self.pairs(("introduced", "0"), ("fixed", "3.3.2-r0"))[0], [("0", "3.3.2-r0")])
        # OSV Alpine `introduced` is an UPSTREAM version (no -rN); kept as is.
        self.assertEqual(self.pairs(("introduced", "2.9.2"), ("fixed", "2.9.4-r0"))[0], [("2.9.2", "2.9.4-r0")])

    def test_multi_fixed_is_one_row_and_the_rest_counted(self):
        # intel-ucode, as OSV has it: only [0, 20190514a-r0) is affected.
        pairs, counters = self.pairs(("introduced", "0"), ("fixed", "20190514a-r0"), ("fixed", "20190618-r0"),
                                     ("fixed", "20191112-r0"))
        self.assertEqual(pairs, [("0", "20190514a-r0")])
        self.assertEqual(counters["redundant fixed"], 2)
        self.assertEqual(counters["shape [introduced 0, fixed, fixed, fixed]"], 1)

    def test_events_sorted_by_apk_version(self):
        # chromium ALPINE-CVE-2022-2163 lists the higher fixed first; OSV evaluates events in version order.
        pairs, counters = self.pairs(("introduced", "0"), ("fixed", "103.0.5060.134-r0"),
                                     ("fixed", "103.0.5060.53-r0"))
        self.assertEqual(pairs, [("0", "103.0.5060.53-r0")])
        self.assertEqual(counters["redundant fixed"], 1)
        # prosody ALPINE-CVE-2026-43506: a fixed below its introduced is an empty range: no row.
        pairs, counters = self.pairs(("introduced", "13.0.0"), ("fixed", "0.12.6-r0"))
        self.assertEqual(pairs, [])
        self.assertEqual(counters["empty range (fixed below introduced)"], 1)
        # Two separate ranges in one entry.
        pairs, _ = self.pairs(("introduced", "0"), ("fixed", "1.0-r0"), ("introduced", "2.0"), ("fixed", "2.1-r0"))
        self.assertEqual(pairs, [("0", "1.0-r0"), ("2.0", "2.1-r0")])

    def test_bad_versions_walk_unsorted(self):
        pairs, counters = self.pairs(("introduced", "7.0.0-0"), ("fixed", "7.1.0.10-r0"))
        self.assertEqual(pairs, [("7.0.0-0", "7.1.0.10-r0")])      # resolve() rejects it
        self.assertEqual(counters["ranges walked unsorted (a bad version)"], 1)

    def test_unknown_shapes_raise(self):
        for bad in (entry(("introduced", "0"), ("last_affected", "1.0-r0")),
                    entry(("introduced", "0"), ("limit", "1.0-r0")),
                    {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]},
                    {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
                    {"ranges": []}, {},
                    {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "1.0"}]}]}):
            with self.subTest(bad=bad), self.assertRaises(osvfeed.ShapeError):
                osvfeed.apk_range_pairs(bad, collections.Counter())


class IngestAndResolve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-apk-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_release(self, records):
        path = os.path.join(self.tmp, "all.zip")
        write_zip(path, records)
        cands, info, stats, shapes, _ = osvfeed.ingest(path, [ALP], helpers_log())
        counters, decisions = collections.Counter(), collections.Counter()
        rows, _, dropped = osvfeed.resolve_apk(ALP, cands[ALP.key], info, counters, decisions)
        return rows, counters, decisions, stats, shapes, dropped

    def test_rows_and_grouping(self):
        rows, counters, decisions, stats, shapes, _ = self.run_release([
            record("ALPINE-CVE-2024-1001", [affected(ECO, "openssl", [{"introduced": "0"}, {"fixed": "3.3.2-r0"}])],
                   upstream=["CVE-2024-1001"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
            record("ALPINE-CVE-2024-1003", [affected(ECO, "openssl", [{"introduced": "0"}, {"fixed": "3.3.2-r0"}])],
                   upstream=["CVE-2024-1003"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}]),
            record("ALPINE-CVE-2024-1002", [affected(ECO, "openssl", [{"introduced": "3.3.0"}, {"fixed": "3.3.2-r1"}])],
                   upstream=["CVE-2024-1002"], severity=[{"type": "CVSS_V4", "score":
                       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]),
            record("ALPINE-CVE-2024-1004", [affected(ECO, "wpa_supplicant", [{"introduced": "0"}, {"fixed": "2.10-r0"}])],
                   upstream=["CVE-2024-1004"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
            record("ALPINE-CVE-2024-1005", [affected("Alpine:v3.19", "openssl", [{"introduced": "0"}, {"fixed": "1-r0"}])],
                   upstream=["CVE-2024-1005"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
        ])
        self.assertEqual(shapes, [])
        body = osvfeed.release_body(ALP, rows)
        self.assertEqual(body["pkgs"], {
            "openssl": [["0", "3.3.2-r0", 4, ["CVE-2024-1001", "CVE-2024-1003"]], ["3.3.0", "3.3.2-r1", 4, ["CVE-2024-1002"]]],
            "wpa_supplicant": [["0", "2.10-r0", 3, ["CVE-2024-1004"]]]})
        self.assertEqual((body["format"], body["keyedBy"]), ("apk", "origin"))
        self.assertEqual(decisions, {"cvss": 4})

    def test_severity_chain_cvss_else_medium(self):
        rows, counters, decisions, _, _, dropped = self.run_release([
            record("ALPINE-CVE-2024-1006", [affected(ECO, "zlib", [{"introduced": "0"}, {"fixed": "1.3.1-r0"}])],
                   upstream=["CVE-2024-1006"]),                                                # no score: Medium
            record("ALPINE-CVE-2024-1007", [affected(ECO, "zlib", [{"introduced": "0"}, {"fixed": "1.3.1-r1"}])],
                   upstream=["CVE-2024-1007"], severity=[{"type": "CVSS_V3", "score": CVSS_MED}]),
        ])
        self.assertEqual(rows, [])
        self.assertEqual(decisions, {"default medium": 1, "cvss": 1})
        self.assertEqual(counters["below High (dropped)"], 2)
        self.assertEqual({d[3] for d in dropped}, {"below High (dropped)"})

    def test_bad_versions_rejected(self):
        high = [{"type": "CVSS_V3", "score": CVSS_HIGH}]
        rows, counters, _, _, _, _ = self.run_release([
            record("ALPINE-CVE-2019-1", [affected(ECO, "imagemagick", [{"introduced": "7.0.0-0"},
                                                                      {"fixed": "7.1.0.10-r0"}])],
                   upstream=["CVE-2019-1"], severity=high),
            record("ALPINE-CVE-2019-2", [affected(ECO, "libdwarf", [{"introduced": "1999-12-14"},
                                                                   {"fixed": "0.6.0-r0"}])],
                   upstream=["CVE-2019-2"], severity=high),
            record("ALPINE-CVE-2020-7247", [affected(ECO, "opensmtpd", [{"introduced": "0"},
                                                                       {"fixed": "6.6.2p1-r0"}])],
                   upstream=["CVE-2020-7247"], severity=high),
            record("ALPINE-CVE-2024-1009", [affected(ECO, "tiff", [{"introduced": "0"}, {"fixed": "2024-08-16"}])],
                   upstream=["CVE-2024-1009"], severity=high),
            record("ALPINE-CVE-2024-10010", [affected(ECO, "curl", [{"introduced": "0"}, {"fixed": "8.9.1-r0"}])],
                   upstream=["CVE-2024-10010"], severity=high),
        ])
        self.assertEqual([r["source"] for r in rows], ["curl"])
        self.assertEqual(counters["rejected"], 4)
        self.assertEqual(counters["rejected: introduced not an apk version"], 1)
        self.assertEqual(counters["rejected: date-shaped"], 2)
        self.assertEqual(counters["rejected: fixed not an apk version"], 1)

    def test_kernel_fold(self):
        rows, counters, _, _, _, _ = self.run_release([
            record("ALPINE-CVE-2024-10020", [affected(ECO, "linux-lts", [{"introduced": "0"}, {"fixed": "6.6.58-r0"}])],
                   upstream=["CVE-2024-10020"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}]),
            record("ALPINE-CVE-2024-10021", [affected(ECO, "linux-lts", [{"introduced": "0"}, {"fixed": "6.6.58-r0"}])],
                   upstream=["CVE-2024-10021"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
            record("ALPINE-CVE-2024-10022", [affected(ECO, "linux-pam", [{"introduced": "0"}, {"fixed": "1.6.0-r0"}])],
                   upstream=["CVE-2024-10022"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
        ])
        body = osvfeed.release_body(ALP, rows)
        self.assertEqual(body["kernel"], {"linux-lts": [["0", "6.6.58-r0", 4, 2, None]]})
        self.assertEqual(body["pkgs"], {"linux-pam": [["0", "1.6.0-r0", 3, ["CVE-2024-10022"]]]})
        self.assertEqual(counters["kernel rows"], 1)

    def test_kernel_names(self):
        for name in sorted(osvfeed.APK_KERNELS):
            self.assertTrue(osvfeed.is_kernel(name, "apk"), name)
        for name in ("linux-pam", "linux-headers", "linux-firmware", "linux-firmware-intel", "linux-tools",
                     "util-linux", "linux"):
            self.assertFalse(osvfeed.is_kernel(name, "apk"), name)

    def test_ids_and_withdrawn(self):
        high = [{"type": "CVSS_V3", "score": CVSS_HIGH}]
        rows, _, _, stats, _, _ = self.run_release([
            record("ALPINE-CVE-2024-10030", [affected(ECO, "xz", [{"introduced": "0"}, {"fixed": "5.6.2-r0"}])],
                   severity=high),                                       # no upstream: the CVE part of the id
            record("ALPINE-CVE-2024-10031", [affected(ECO, "xz", [{"introduced": "0"}, {"fixed": "5.6.3-r0"}])],
                   upstream=["CVE-2024-10031"], severity=high, withdrawn="2024-12-01T00:00:00Z"),
        ])
        self.assertEqual([(r["source"], r["fixed"], r["ids"]) for r in rows], [("xz", "5.6.2-r0", ["CVE-2024-10030"])])
        self.assertEqual(stats["withdrawn records skipped"], 1)

    def test_unknown_shape_counted(self):
        _, _, _, stats, shapes, _ = self.run_release([
            record("ALPINE-CVE-2024-10040", [affected(ECO, "xz", [{"introduced": "0"}, {"last_affected": "5.6.1-r0"}])],
                   upstream=["CVE-2024-10040"]),
            record("ALPINE-CVE-2024-10041", [affected(ECO, "Bad Name", [{"introduced": "0"}, {"fixed": "1-r0"}])],
                   upstream=["CVE-2024-10041"])])
        self.assertEqual(stats["alpine-3.22: unknown range shape"], 2)
        self.assertEqual(len(shapes), 2)


class ReleaseBody(unittest.TestCase):
    ENTRY = {"format": "apk", "file": "r/alpine-3.22-x.json", "rows": 3}

    def body(self):
        return {"release": "alpine-3.22", "format": "apk", "keyedBy": "origin",
                "pkgs": {"openssl": [["0", "3.3.2-r0", 3, ["CVE-2024-1001"]], ["3.3.0", "3.3.2-r1", 4, ["CVE-2024-1002"]]]},
                "kernel": {"linux-lts": [["0", "6.6.58-r0", 4, 12, None]]}}

    def check(self, body, key="alpine-3.22", entry=None):
        osvfeed.check_release_body(json.loads(json.dumps(body)), key, entry or self.ENTRY)

    def test_accepts_the_contract_example(self):
        self.check(self.body())
        body = self.body()
        body["pkgs"]["wpa_supplicant"] = [["0", "2.10-r0", 3, ["CVE-2024-1004"]]]
        self.check(body, entry=dict(self.ENTRY, rows=4))

    def test_refusals(self):
        def bad(change, why, key="alpine-3.22", entry=None):
            body = self.body()
            change(body)
            with self.subTest(why=why), self.assertRaisesRegex(FeedError, why):
                self.check(body, key, entry)
        bad(lambda b: b.update(keyedBy="source"), "do not match")
        bad(lambda b: b.update(format="dpkg"), "do not match")                      # a dpkg body named apk
        bad(lambda b: None, "do not match", entry=dict(self.ENTRY, format="dpkg"))   # a dpkg entry for Alpine
        bad(lambda b: b.update(release="debian-12"), "do not match", key="debian-12")  # apk body for debian
        bad(lambda b: b["pkgs"]["openssl"][0].__setitem__(1, "3.3.2-1"), "bad version")
        bad(lambda b: b["pkgs"]["openssl"][1].__setitem__(0, "7.0.0-0"), "bad version")
        bad(lambda b: b["pkgs"]["openssl"][1].__setitem__(0, "2024-01-01"), "bad version")
        bad(lambda b: b["pkgs"]["openssl"][0].__setitem__(3, ["ALPINE-CVE-2024-1001"]), "bad ids")
        bad(lambda b: b["pkgs"]["openssl"][0].__setitem__(3, ["USN-1-1"]), "bad ids")
        bad(lambda b: b["kernel"]["linux-lts"][0].__setitem__(4, "2024-10-01"), "bad kernel row")
        bad(lambda b: b["pkgs"].update({"linux-lts": b["kernel"].pop("linux-lts")}), "bad pkgs source")
        bad(lambda b: b["kernel"].update({"linux-pam": b["kernel"].pop("linux-lts")}), "bad kernel source")
        bad(lambda b: b["pkgs"]["openssl"][0].__setitem__(2, 2), "not High or Critical")

    def test_dpkg_bodies_unchanged(self):
        body = {"release": "debian-12", "format": "dpkg", "keyedBy": "source",
                "pkgs": {"apt": [["0", "2.6.2", 3, ["CVE-2026-109518"]]]},
                "kernel": {"linux": [["0", "6.1.158-1", 4, 2, "2026-10-30"]]}}
        osvfeed.check_release_body(body, "debian-12", {"format": "dpkg", "file": "x", "rows": 2})
        with self.assertRaisesRegex(FeedError, "do not match"):
            osvfeed.check_release_body(dict(body, format="apk", keyedBy="origin"), "debian-12",
                                       {"format": "apk", "file": "x", "rows": 2})


LISTING = """# a header line
P:busybox
V:1.36.1-r28
o:busybox

P:busybox-binsh
V:1.36.1-r29
o:busybox

P:libcrypto3
V:3.3.0-r2
o:openssl

P:noorigin
V:1.0-r0

"""


class Golden(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-apk-golden-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def test_listing_parser(self):
        inv = osvfeed.read_apk_inventory(self.write("l.apk.txt", LISTING))
        self.assertEqual(inv, {"busybox": "1.36.1-r29", "openssl": "3.3.0-r2", "noorigin": "1.0-r0"})
        for bad in ("P:x\n\n", "X:y\n", "P:a\nP:b\nV:1\n"):
            with self.subTest(bad=bad), self.assertRaises(FeedError):
                osvfeed.read_apk_inventory(self.write("b.apk.txt", bad))

    def test_matcher(self):
        inv = {"openssl": "3.3.0-r2", "musl": "1.2.5-r0", "zlib": "1.3.2-r1", "linux-lts": "6.6.1-r0"}
        body = {"pkgs": {"openssl": [["0", "3.3.0-r3", 3, ["CVE-1"]], ["3.4.0", "3.4.1-r0", 3, ["CVE-2"]],
                                     ["3.3.0", "3.3.2-r0", 3, ["CVE-3"]]],
                         "musl": [["1.2.6", "1.2.6-r1", 3, ["CVE-4"]]],
                         "zlib": [["0", "1.3.2-r1", 3, ["CVE-5"]]]},
                "kernel": {"linux-lts": [["0", "6.6.58-r0", 4, 2, None]]}}
        self.assertEqual(osvfeed.apk_hits(body, inv), {"openssl": ["3.3.0-r3", "3.3.2-r0"]})

    def test_real_fixtures(self):
        cases = [c for c in osvfeed.golden_cases() if osvfeed.FORMAT_OF[c["release"]] == "apk"]
        self.assertEqual(len(cases), 3)
        for case in cases:
            path = os.path.join(osvfeed.GOLDEN_DIR, case["fixture"])
            self.assertLess(os.path.getsize(path), 16 * 1024)
            with open(path) as handle:
                header = handle.readline()
            self.assertRegex(header, r"^# Stock alpine:\S+ \(alpine@sha256:[0-9a-f]{64}, .*alpine-release 3\.\d+\.\d+")
            inv = osvfeed.read_apk_inventory(path)
            self.assertIn("busybox", inv)
            self.assertIn("openssl", inv)
            self.assertNotIn("archive", case, "no archive snapshot for Alpine")

    def test_check_golden_apk(self):
        self.write("l.apk.txt", LISTING)
        with open(os.path.join(self.tmp, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "l.apk.txt", "release": "alpine-3.22", "capture": "2026-11-05",
                                  "atLeast": ["openssl"]}]}, handle)
        row = {"source": "openssl", "introduced": "0", "fixed": "3.3.0-r3", "severity": 3, "ids": ["CVE-1"],
               "kernel": False, "date": "2030-01-01", "rules": {"CVE-1": "cvss"}}
        log = helpers_log()
        # No date filter: Alpine has no fix dates (the record date of a row is the CVE's).
        self.assertEqual(osvfeed.check_golden("alpine-3.22", [row], log, self.tmp), [])
        self.assertIn("missing ['openssl']", osvfeed.check_golden("alpine-3.22", [], log, self.tmp)[0])


class Config(unittest.TestCase):
    def test_releases(self):
        keys = [r.key for r in osvfeed.RELEASES if r.family == "alpine"]
        self.assertEqual(keys, ["alpine-3.20", "alpine-3.21", "alpine-3.22", "alpine-3.23", "alpine-3.24"])
        for release in osvfeed.RELEASES:
            if release.family == "alpine":
                self.assertEqual((release.format, release.osv_zip, release.ecosystem),
                                 ("apk", "Alpine", "Alpine:v" + release.key.split("-")[1]))

    def test_manifest_sources_and_format(self):
        apk_entry = {"format": "apk", "file": "r/alpine-3.22-0123456789abcdef.json", "sha256": "a" * 64,
                     "bytes": 10, "rows": 1}
        only_apk = {"osv": {"Alpine": "2026-11-05T09:30:02Z"}, "archive": {}, "baseline": {}}
        build.check_sources(only_apk, {"alpine-3.22": apk_entry})
        with self.assertRaisesRegex(FeedError, "sources.archive"):
            build.check_sources(only_apk, {"alpine-3.22": apk_entry,
                                           "debian-12": dict(apk_entry, format="dpkg")})
        mixed = dict(helpers.FAKE_SOURCES, osv={"Debian": "2026-11-05T13:03:11Z", "Alpine": "2026-11-05T09:30:02Z"})
        build.check_sources(mixed, {"alpine-3.22": apk_entry})
        with self.assertRaisesRegex(FeedError, "sources.osv"):
            build.check_sources(dict(mixed, osv={"Arch": "2026-11-05T13:03:11Z"}), {"alpine-3.22": apk_entry})


class EndToEnd(unittest.TestCase):
    """build_releases() for one Alpine release over a file:// OSV zip: no archive, no baseline, no gpg."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vulnfeed-apk-e2e-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.osv = os.path.join(self.tmp, "osv", "Alpine")
        os.makedirs(self.osv)
        self.write_osv([
            record("ALPINE-CVE-2024-1001", [affected(ECO, "openssl", [{"introduced": "0"}, {"fixed": "3.3.2-r0"}])],
                   upstream=["CVE-2024-1001"], severity=[{"type": "CVSS_V3", "score": CVSS_HIGH}]),
            record("ALPINE-CVE-2024-10020", [affected(ECO, "linux-lts", [{"introduced": "0"}, {"fixed": "6.6.58-r0"}])],
                   upstream=["CVE-2024-10020"], severity=[{"type": "CVSS_V3", "score": CVSS_CRIT}],
                   modified="2026-11-05T09:30:02Z"),
        ], "2026-11-05T09:30:02Z")
        self.golden = os.path.join(self.tmp, "golden")
        os.makedirs(self.golden)
        with open(os.path.join(self.golden, "inv.apk.txt"), "w") as handle:
            handle.write("P:libcrypto3\nV:3.3.0-r2\no:openssl\n\n")
        with open(os.path.join(self.golden, "expected.json"), "w") as handle:
            json.dump({"cases": [{"fixture": "inv.apk.txt", "release": "alpine-3.22", "capture": "2026-11-05",
                                  "atLeast": ["openssl"]}]}, handle)
        self.gates = os.path.join(self.tmp, "gates")
        os.makedirs(self.gates)
        with open(os.path.join(self.gates, "minimums.json"), "w") as handle:
            json.dump({"minimums": {"alpine-3.22": 1}}, handle)
        with open(os.path.join(self.gates, "overrides.json"), "w") as handle:
            json.dump({"rowCount": []}, handle)
        old = netfetch.OSV_BASE
        netfetch.OSV_BASE = "file://" + os.path.join(self.tmp, "osv")
        self.addCleanup(setattr, netfetch, "OSV_BASE", old)

    def write_osv(self, records, newest):
        write_zip(os.path.join(self.osv, "all.zip"), records)
        with open(os.path.join(self.osv, "modified_id.csv"), "w") as handle:
            handle.write(f"{newest},ALPINE-CVE-2024-10020\n")

    def run_build(self, cache="cache"):
        site = os.path.join(self.tmp, "site", "v1")
        result = osvfeed.build_releases(site, helpers_log(), os.path.join(self.tmp, cache),
                                        os.path.join(self.tmp, "work"), releases=[ALP], golden_dir=self.golden,
                                        gates_dir=self.gates, today="2026-11-05")
        return site, result

    def test_build(self):
        site, (releases, sources, failures) = self.run_build()
        self.assertEqual(failures, {})
        entry = releases["alpine-3.22"]
        self.assertEqual((entry["format"], entry["rows"]), ("apk", 2))
        with open(os.path.join(site, entry["file"]), "rb") as handle:
            body = json.loads(handle.read())
        self.assertEqual(body, {"release": "alpine-3.22", "format": "apk", "keyedBy": "origin",
                                "pkgs": {"openssl": [["0", "3.3.2-r0", 3, ["CVE-2024-1001"]]]},
                                "kernel": {"linux-lts": [["0", "6.6.58-r0", 4, 1, None]]}})
        self.assertEqual(sources, {"osv": {"Alpine": "2026-11-05T09:30:02Z"}, "archive": {}, "baseline": {}})

    def test_last_affected_fails_the_release_soft(self):
        self.write_osv([record("ALPINE-CVE-2024-1002", [affected(ECO, "xz", [{"introduced": "0"},
                                                                        {"last_affected": "5.6.1-r0"}])],
                               upstream=["CVE-2024-1002"])], "2027-01-01T00:00:00Z")
        _, (releases, _, failures) = self.run_build(cache="cache2")
        self.assertEqual(releases, {})
        self.assertIn("unknown range shape", failures["alpine-3.22"])

    def test_rejects_over_the_limit_fail_soft(self):
        high = [{"type": "CVSS_V3", "score": CVSS_HIGH}]
        self.write_osv([
            record("ALPINE-CVE-2024-1001", [affected(ECO, "openssl", [{"introduced": "0"}, {"fixed": "3.3.2-r0"}])],
                   upstream=["CVE-2024-1001"], severity=high),
            record("ALPINE-CVE-2024-1003", [affected(ECO, "imagemagick", [{"introduced": "7.0.0-0"},
                                                                      {"fixed": "7.1.0.10-r0"}])],
                   upstream=["CVE-2024-1003"], severity=high)], "2027-01-01T00:00:00Z")
        _, (releases, _, failures) = self.run_build(cache="cache3")
        self.assertIn("unparseable introduced, the limit is 2.0%", failures["alpine-3.22"])
        self.write_osv([
            record("ALPINE-CVE-2024-1001", [affected(ECO, "openssl", [{"introduced": "0"}, {"fixed": "3.3.2-r0"}])],
                   upstream=["CVE-2024-1001"], severity=high),
            record("ALPINE-CVE-2024-1003", [affected(ECO, "tiff", [{"introduced": "0"}, {"fixed": "2024-08-16"}])],
                   upstream=["CVE-2024-1003"], severity=high)], "2027-01-02T00:00:00Z")
        _, (releases, _, failures) = self.run_build(cache="cache4")
        self.assertIn("of fixed versions rejected, the limit is 0.5%", failures["alpine-3.22"])


if __name__ == "__main__":
    unittest.main()
