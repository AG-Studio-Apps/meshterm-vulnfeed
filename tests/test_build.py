import hashlib
import json
import os
import shutil
import tempfile
import unittest

import helpers
import build
from feedlib import FeedError, dumps

NOW = "2026-11-05T05:10:00Z"


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.out = os.path.join(self.repo, "out")
        self.addCleanup(shutil.rmtree, self.repo)

    def run_build(self, now=NOW, live=None, carry=None):
        log = build.Log(echo=False)
        manifest, record = build.build(self.repo, self.out, helpers.COMMIT, now, live, carry, log,
                                       helpers.no_releases())
        return manifest, record

    def commit_record(self, record):
        with open(os.path.join(self.repo, "builds", f"{record['serial']}.json"), "wb") as handle:
            handle.write(dumps(record))

    def test_manifest_shape(self):
        manifest, record = self.run_build()
        self.assertEqual(set(manifest), {"schema", "version", "serial", "generated", "sources", "releases",
                                         "curated"})
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["serial"], 1)
        self.assertEqual(manifest["version"], manifest["serial"])
        self.assertEqual(manifest["generated"], NOW)
        self.assertEqual(manifest["releases"], {})
        self.assertEqual(set(manifest["curated"]), {"file", "sha256"})
        with open(os.path.join(self.out, "v1", "manifest.json"), "rb") as handle:
            on_disk = handle.read()
        self.assertEqual(json.loads(on_disk), manifest)
        self.assertEqual(on_disk, dumps(manifest))
        self.assertEqual(record["manifest"], manifest)
        self.assertEqual(record["commit"], helpers.COMMIT)

    def test_curated_sha256_matches_file(self):
        manifest, _ = self.run_build()
        name = manifest["curated"]["file"]
        with open(os.path.join(self.out, "v1", name), "rb") as handle:
            data = handle.read()
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(manifest["curated"]["sha256"], digest)
        self.assertEqual(name, f"curated-{digest[:16]}.json")
        with open(os.path.join(self.repo, "curated", "curated.json"), "rb") as handle:
            self.assertEqual(data, handle.read(), "the published curated file is a byte copy")

    def test_serial_increments_from_builds_history(self):
        _, record = self.run_build()
        self.commit_record(record)
        manifest, record = self.run_build(now="2026-11-05T17:10:00Z")
        self.assertEqual(manifest["serial"], 2)
        self.commit_record(record)
        manifest, _ = self.run_build(now="2026-11-06T05:10:00Z")
        self.assertEqual(manifest["serial"], 3)

    def test_serial_floored_by_live_manifest(self):
        _, record = self.run_build()
        self.commit_record(record)
        manifest, _ = self.run_build(live={"serial": 5})
        self.assertEqual(manifest["serial"], 6)

    def test_live_serial_far_ahead_refused(self):
        with self.assertRaisesRegex(FeedError, "investigate"):
            self.run_build(live={"serial": 1000})

    def test_inconsistent_history_refused(self):
        with open(os.path.join(self.repo, "builds", "4.json"), "wb") as handle:
            handle.write(dumps({"serial": 3}))
        with self.assertRaisesRegex(FeedError, "does not record serial 4"):
            self.run_build()

    def test_keeps_last_three_builds_files(self):
        site = tempfile.mkdtemp(prefix="vulnfeed-live-")
        self.addCleanup(shutil.rmtree, site)
        curated_path = os.path.join(self.repo, "curated", "curated.json")
        names = []
        for n in range(4):
            with open(curated_path) as handle:
                doc = json.load(handle)
            doc["rules"][0]["title"] = f"Tailscale security update {n}"
            with open(curated_path, "w") as handle:
                json.dump(doc, handle)
            manifest, record = self.run_build(carry=site)
            names.append(manifest["curated"]["file"])
            self.commit_record(record)
            shutil.rmtree(site)
            shutil.copytree(self.out, site)  # "deploy"
        present = sorted(f for f in os.listdir(os.path.join(self.out, "v1")) if f.startswith("curated-"))
        self.assertEqual(present, sorted(names[1:]), "the current build plus the two before it")

    def test_carry_rejects_a_tampered_file(self):
        site = tempfile.mkdtemp(prefix="vulnfeed-live-")
        self.addCleanup(shutil.rmtree, site)
        _, record = self.run_build()
        self.commit_record(record)
        shutil.copytree(self.out, site, dirs_exist_ok=True)
        old = record["manifest"]["curated"]["file"]
        with open(os.path.join(site, "v1", old), "ab") as handle:
            handle.write(b" ")
        with open(os.path.join(self.repo, "curated", "curated.json"), "ab") as handle:
            handle.write(b"\n")
        log = build.Log(echo=False)
        build.build(self.repo, self.out, helpers.COMMIT, NOW, None, site, log, helpers.no_releases())
        self.assertFalse(os.path.exists(os.path.join(self.out, "v1", old)))
        self.assertTrue(any("sha256 does not match" in w for w in log.warnings))

    def test_invalid_curated_fails_the_build(self):
        with open(os.path.join(self.repo, "curated", "curated.json"), "w") as handle:
            json.dump({"rules": [{"id": "x-y-z", "command": "sh"}]}, handle)
        with self.assertRaises(FeedError):
            self.run_build()

    def test_bad_commit_and_time_refused(self):
        with self.assertRaises(FeedError):
            build.build(self.repo, self.out, "main", NOW, options=helpers.no_releases())
        with self.assertRaises(FeedError):
            build.build(self.repo, self.out, helpers.COMMIT, "2026-11-05 05:10", options=helpers.no_releases())


class GateTests(unittest.TestCase):
    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.out = os.path.join(self.repo, "out")
        self.addCleanup(shutil.rmtree, self.repo)
        self.manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                       options=helpers.no_releases())
        self.v1 = os.path.join(self.out, "v1")

    def rewrite(self, manifest):
        with open(os.path.join(self.v1, "manifest.json"), "wb") as handle:
            handle.write(dumps(manifest))

    def test_good_site_passes(self):
        build.gate(self.out, build.Log(echo=False))

    def test_tampered_curated_fails(self):
        with open(os.path.join(self.v1, self.manifest["curated"]["file"]), "ab") as handle:
            handle.write(b" ")
        with self.assertRaisesRegex(FeedError, "sha256"):
            build.gate(self.out, build.Log(echo=False))

    def test_oversized_file_fails(self):
        manifest = dict(self.manifest)
        big = b"x" * (build.FILE_CAP + 1)
        digest = hashlib.sha256(big).hexdigest()
        name = f"r/ubuntu-24.04-{digest[:16]}.json"
        os.makedirs(os.path.join(self.v1, "r"))
        with open(os.path.join(self.v1, name), "wb") as handle:
            handle.write(big)
        manifest["releases"] = {"ubuntu-24.04": {"format": "dpkg", "file": name, "sha256": digest,
                                                 "bytes": len(big), "rows": 1}}
        manifest["sources"] = helpers.FAKE_SOURCES
        self.rewrite(manifest)
        with self.assertRaisesRegex(FeedError, "at most"):
            build.gate(self.out, build.Log(echo=False))

    def test_shape_violations_fail(self):
        cases = {
            "schema": dict(self.manifest, schema=2),
            "version": dict(self.manifest, version=self.manifest["serial"] + 1),
            "generated": dict(self.manifest, generated="yesterday"),
            "keys": dict(self.manifest, extra=1),
            "release format": dict(self.manifest, releases={"x": {"format": "msi", "file": "r/x-0123456789abcdef.json",
                                                                  "sha256": "0" * 64, "bytes": 1, "rows": 1}}),
        }
        for label, manifest in cases.items():
            with self.subTest(label=label):
                self.rewrite(manifest)
                with self.assertRaises(FeedError):
                    build.gate(self.out, build.Log(echo=False))

    def test_unexpected_file_fails(self):
        with open(os.path.join(self.v1, "install.sh"), "w") as handle:
            handle.write("echo")
        with self.assertRaisesRegex(FeedError, "unexpected file"):
            build.gate(self.out, build.Log(echo=False))

    def test_symlink_fails(self):
        os.symlink("/etc/passwd", os.path.join(self.v1, "curated-0000000000000000.json"))
        with self.assertRaisesRegex(FeedError, "symlink"):
            build.gate(self.out, build.Log(echo=False))


class ReleaseTests(unittest.TestCase):
    """The manifest and gate with S2 release files (a fake S2 step, no network)."""

    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.out = os.path.join(self.repo, "out")
        self.addCleanup(shutil.rmtree, self.repo)
        self.seen = []
        self.manifest, self.record = build.build(self.repo, self.out, helpers.COMMIT, NOW,
                                                 log=build.Log(echo=False),
                                                 options=helpers.fake_releases(self.seen))
        self.v1 = os.path.join(self.out, "v1")

    def rewrite(self, manifest):
        with open(os.path.join(self.v1, "manifest.json"), "wb") as handle:
            handle.write(dumps(manifest))

    def test_release_entry_and_sources(self):
        entry = self.manifest["releases"]["debian-12"]
        self.assertEqual(set(entry), {"format", "file", "sha256", "bytes", "rows"})
        with open(os.path.join(self.v1, entry["file"]), "rb") as handle:
            data = handle.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
        self.assertEqual(entry["file"], f"r/debian-12-{entry['sha256'][:16]}.json")
        self.assertEqual(entry["bytes"], len(data))
        self.assertEqual(self.manifest["sources"], helpers.FAKE_SOURCES)
        self.assertEqual(self.seen, [None], "the first build has no previous releases")

    def test_previous_releases_passed_on(self):
        with open(os.path.join(self.repo, "builds", "1.json"), "wb") as handle:
            handle.write(dumps(self.record))
        build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                    options=helpers.fake_releases(self.seen))
        self.assertEqual(self.seen[-1], self.manifest["releases"])

    def test_release_files_carried(self):
        site = tempfile.mkdtemp(prefix="vulnfeed-live-")
        self.addCleanup(shutil.rmtree, site)
        shutil.copytree(self.out, site, dirs_exist_ok=True)
        with open(os.path.join(self.repo, "builds", "1.json"), "wb") as handle:
            handle.write(dumps(self.record))

        def other(site_v1, log, previous):
            return {}, {}
        manifest, record = build.build(self.repo, self.out, helpers.COMMIT, NOW, None, site,
                                       build.Log(echo=False), build.ReleaseOptions(builder=other))
        self.assertIn(self.manifest["releases"]["debian-12"]["file"], record["carried"])

    def test_gate_passes(self):
        build.gate(self.out, build.Log(echo=False))

    def test_tampered_release_file_fails(self):
        entry = self.manifest["releases"]["debian-12"]
        with open(os.path.join(self.v1, entry["file"]), "ab") as handle:
            handle.write(b" ")
        with self.assertRaisesRegex(FeedError, "sha256"):
            build.gate(self.out, build.Log(echo=False))

    def test_release_body_schema_checked(self):
        entry = dict(self.manifest["releases"]["debian-12"])
        body = {"release": "debian-12", "format": "dpkg", "keyedBy": "source",
                "pkgs": {"apt": [["0", "2.6.2", 2, ["CVE-2026-109518"]]]}, "kernel": {}}
        data = json.dumps(body).encode()
        digest = hashlib.sha256(data).hexdigest()
        name = f"r/debian-12-{digest[:16]}.json"
        with open(os.path.join(self.v1, name), "wb") as handle:
            handle.write(data)
        os.remove(os.path.join(self.v1, entry["file"]))
        entry.update(file=name, sha256=digest, bytes=len(data), rows=1)
        self.rewrite(dict(self.manifest, releases={"debian-12": entry}))
        with self.assertRaisesRegex(FeedError, "not High or Critical"):
            build.gate(self.out, build.Log(echo=False))

    def test_manifest_release_and_sources_shapes(self):
        entry = self.manifest["releases"]["debian-12"]
        cases = {
            "not allowlisted": dict(self.manifest, releases={"debian-99": dict(entry)}),
            "sources missing a key": dict(self.manifest, sources={"osv": {"Debian": "2026-11-05T13:03:11Z"}}),
            "sources osv bad key": dict(self.manifest, sources=dict(helpers.FAKE_SOURCES,
                                                                    osv={"Arch": "2026-11-05T13:03:11Z"})),
            "sources archive bad time": dict(self.manifest, sources=dict(helpers.FAKE_SOURCES,
                                                                         archive={"bookworm": "yesterday"})),
            "sources baseline unknown": dict(self.manifest, sources=dict(helpers.FAKE_SOURCES,
                                                                         baseline={"debian-99": "2023-06-10"})),
            "sources without releases": dict(self.manifest, releases={}),
        }
        for label, manifest in cases.items():
            with self.subTest(label=label):
                self.rewrite(manifest)
                with self.assertRaises(FeedError):
                    build.gate(self.out, build.Log(echo=False))


class SeamTests(unittest.TestCase):
    def test_the_builder_option_replaces_s2(self):
        options = build.ReleaseOptions(builder=lambda site_v1, log, previous: ({}, {"seen": previous}))
        self.assertEqual(build.build_releases("/nonexistent", build.Log(echo=False), options, {"x": 1}),
                         ({}, {"seen": {"x": 1}}))


if __name__ == "__main__":
    unittest.main()
