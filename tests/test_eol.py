"""S6: the end-of-life table (builder/eol.py), the manifest fields it sets and check_manifest's rules for them."""
import json
import os
import shutil
import unittest

import helpers
import build
import eol
import osvfeed
from feedlib import FeedError

NOW = "2026-11-05T05:10:00Z"
# Release keys that deliberately carry no date (none today; add a key here, with the reason, to leave it out).
NO_DATE = {}


class Table(unittest.TestCase):
    def test_every_release_key_is_covered(self):
        for key in osvfeed.RELEASE_KEYS:
            with self.subTest(key=key):
                if key.endswith("-esm"):
                    self.assertNotIn(key, eol.TABLE, "the -esm entries carry neither field")
                else:
                    self.assertTrue((key in eol.TABLE) != (key in NO_DATE), "a table entry or deliberately absent")
        self.assertLessEqual(set(eol.TABLE), set(osvfeed.RELEASE_KEYS), "no entry for a key the feed does not have")

    def test_entries_are_well_formed(self):
        for key, entry in eol.TABLE.items():
            with self.subTest(key=key):
                self.assertLessEqual(set(entry), {"eol", "eolPro", "source", "read"})
                self.assertTrue(eol.is_day(entry["eol"]))
                self.assertTrue(eol.is_day(entry["read"]))
                self.assertTrue(isinstance(entry["source"], str) and entry["source"])
                self.assertIsNone(eol.check_fields(key, eol.fields(key)))
                if "eolPro" in entry:
                    self.assertTrue(key.startswith("ubuntu-") and not key.endswith("-esm"))
                    self.assertGreaterEqual(entry["eolPro"], entry["eol"])

    def test_pro_dates_for_every_lts_with_pro(self):
        for key in ("ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"):
            self.assertIn("eolPro", eol.TABLE[key])
        self.assertNotIn("eolPro", eol.TABLE["ubuntu-26.10"])

    def test_known_dates(self):
        self.assertEqual(eol.fields("ubuntu-24.04"), {"eol": "2029-05-31", "eolPro": "2034-04-25"})
        self.assertEqual(eol.fields("debian-12"), {"eol": "2028-06-30"})
        self.assertEqual(eol.fields("alma-8"), {"eol": "2029-05-31"})
        self.assertEqual(eol.fields("rhel-8"), eol.fields("alma-8"))
        self.assertEqual(eol.fields("ubuntu-24.04-esm"), {})

    def test_is_day(self):
        for good in ("2029-05-31", "2028-02-29"):
            self.assertTrue(eol.is_day(good))
        for bad in ("2029-02-30", "2027-02-29", "2029-5-31", "2029-05-31T00:00:00Z", "20290531", None, 20290531,
                    "2029-13-01", "2029-05-31\n"):
            self.assertFalse(eol.is_day(bad), bad)

    def test_check_fields(self):
        ok = [("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": "2034-04-25"}),
              ("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": "2029-05-31"}), ("debian-12", {}),
              ("debian-12", {"eol": "2028-06-30"})]
        for key, entry in ok:
            self.assertIsNone(eol.check_fields(key, entry), (key, entry))
        bad = [("debian-12", {"eol": "2028-06-31"}), ("debian-12", {"eol": "2028-06-30", "eolPro": "2030-01-01"}),
               ("ubuntu-24.04-esm", {"eol": "2029-05-31", "eolPro": "2034-04-25"}),
               ("ubuntu-24.04", {"eolPro": "2034-04-25"}),
               ("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": "2029-05-30"}),
               ("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": 2034})]
        for key, entry in bad:
            self.assertIsNotNone(eol.check_fields(key, entry), (key, entry))


class ManifestFields(unittest.TestCase):
    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")

    def test_build_sets_the_fields(self):
        manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                  options=helpers.fake_releases())
        self.assertEqual(manifest["releases"]["debian-12"]["eol"], "2028-06-30")
        self.assertNotIn("eolPro", manifest["releases"]["debian-12"])

    def test_carried_forward_entry_takes_the_table_not_the_old_record(self):
        first, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                               options=helpers.fake_releases())
        old = json.loads(json.dumps(first))
        old["releases"]["debian-12"]["eol"] = "2020-01-01"      # an old record's value
        with open(os.path.join(self.repo, "builds", "1.json"), "w") as handle:
            json.dump({"serial": 1, "manifest": old}, handle)
        live = os.path.join(self.repo, "live")
        shutil.copytree(self.out, live)
        failing = build.ReleaseOptions(builder=lambda site_v1, log, previous, today: (
            {}, {}, {"debian-12": "osv Debian: offline"}))
        manifest, record = build.build(self.repo, self.out, helpers.COMMIT, NOW, None, live, build.Log(echo=False),
                                       failing)
        self.assertIn("debian-12", record["stale"])
        self.assertEqual(manifest["releases"]["debian-12"]["eol"], "2028-06-30")

    def manifest(self):
        manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                  options=helpers.fake_releases())
        return manifest

    def test_check_manifest(self):
        good = self.manifest()
        build.check_manifest(good)
        cases = [
            (lambda e: e.update(eol="2028-06-31"), "is not a YYYY-MM-DD date"),
            (lambda e: e.update(eol="2028-07-01"), "must be builder/eol.py's"),
            (lambda e: e.pop("eol"), "must be builder/eol.py's"),
            (lambda e: e.update(eolPro="2030-01-01"), "eolPro is only for a base Ubuntu release"),
            (lambda e: e.update(eolDate="2028-06-30"), "keys must be"),
        ]
        for change, why in cases:
            with self.subTest(why=why):
                manifest = json.loads(json.dumps(good))
                change(manifest["releases"]["debian-12"])
                with self.assertRaises(FeedError) as caught:
                    build.check_manifest(manifest)
                self.assertIn(why, str(caught.exception))

    def test_check_manifest_ubuntu_pro(self):
        good = self.manifest()
        entry = dict(good["releases"].pop("debian-12"))
        entry.update(file=entry["file"].replace("r/debian-12-", "r/ubuntu-24.04-"))
        good["releases"]["ubuntu-24.04"] = entry
        del entry["eol"]
        entry.update(eol.fields("ubuntu-24.04"))
        build.check_manifest(good)
        for pro, why in (("2029-05-30", "before eol"), ("2034-04-26", "must be builder/eol.py's")):
            with self.subTest(pro=pro):
                manifest = json.loads(json.dumps(good))
                manifest["releases"]["ubuntu-24.04"]["eolPro"] = pro
                with self.assertRaises(FeedError) as caught:
                    build.check_manifest(manifest)
                self.assertIn(why, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
