"""The sign job's inline artifact check (.github/workflows/build.yml), run as CI runs it: python3 -I on the
unpacked site, from a checkout holding curated/curated.json. Also keeps its release allowlist equal to
builder/osvfeed.py RELEASES."""
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import unittest

import helpers
import build
import osvfeed

WORKFLOW = os.path.join(helpers.ROOT, ".github", "workflows", "build.yml")
NOW = "2026-11-05T05:10:00Z"


def sign_check_script():
    lines = open(WORKFLOW, encoding="utf-8").read().split("\n")
    start = next(i for i, line in enumerate(lines) if "Unpack and check the artifact" in line)
    first = next(i for i in range(start, len(lines)) if "python3 -I - <<'PY'" in lines[i])
    last = next(i for i in range(first + 1, len(lines)) if lines[i].strip() == "PY")
    return textwrap.dedent("\n".join(lines[first + 1:last])) + "\n"


class BuilderBugJob(unittest.TestCase):
    """A builder bug publishes (fail-soft) and THEN turns the run red: the job needs deploy and record."""

    def text(self):
        return open(WORKFLOW, encoding="utf-8").read()

    def test_job_shape(self):
        text = self.text()
        job = text[text.index("\n  builder-bug:\n"):]
        self.assertIn("needs: [build, deploy, record]", job)
        self.assertIn("if: always() && needs.build.outputs.bugs != ''", job)
        self.assertIn('echo "::error::builder bug in S2', job)
        self.assertIn("exit 1", job)
        self.assertIn("bugs: ${{ steps.meta.outputs.bugs }}", text)

    def test_bug_list_one_liner(self):
        text = self.text()
        line = next(l for l in text.splitlines() if l.strip().startswith("bugs=$(python3 -I -c"))
        code = line.split("-c '", 1)[1].rsplit("')", 1)[0]
        repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, repo)
        os.makedirs(os.path.join(repo, "record"))
        for bugs, want in ((["debian-12", "ubuntu-24.04"], "debian-12 ubuntu-24.04"), ([], ""),
                           (["x; rm -rf /"], "")):
            with open(os.path.join(repo, "record", "build.json"), "w") as handle:
                json.dump({"bugs": bugs}, handle)
            out = subprocess.run([sys.executable, "-I", "-c", code], cwd=repo, capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), want)


class SignJobCheck(unittest.TestCase):
    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")
        self.manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                       options=helpers.fake_releases())
        self.script = os.path.join(self.repo, "signcheck.py")
        with open(self.script, "w") as handle:
            handle.write(sign_check_script())

    def run_check(self, script=None):
        env = dict(os.environ, SITE=self.out, SERIAL=str(self.manifest["serial"]), DATE=NOW[:10])
        return subprocess.run([sys.executable, "-I", script or self.script], cwd=self.repo, env=env,
                              capture_output=True, text=True)

    def test_retired_set_matches_the_builder(self):
        text = open(WORKFLOW, encoding="utf-8").read()
        match = re.search(r"retired = (set\(\)|\{[^}]*\})", text)
        self.assertIsNotNone(match)
        self.assertEqual(set(re.findall(r'"([a-z0-9.-]+)"', match.group(1))), set(osvfeed.RETIRED_RELEASES))

    def test_rows_must_match_the_body(self):
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        manifest["releases"]["debian-12"]["rows"] = 3
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has 2 rows, the manifest says 3", result.stdout)

    def test_carried_files_must_match_a_build_record(self):
        old = os.path.join(self.out, "v1", "r", "debian-12-00000000000000aa.json")
        with open(old, "w") as handle:
            handle.write("{}")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matches no builds/ record", result.stdout)
        digest = __import__("hashlib").sha256(b"{}").hexdigest()
        record = {"serial": 1, "manifest": {"releases": {"debian-12": {"file": "r/debian-12-00000000000000aa.json",
                                                                       "sha256": digest}}}}
        with open(os.path.join(self.repo, "builds", "1.json"), "w") as handle:
            json.dump(record, handle)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_retiring_a_release_end_to_end(self):
        """The README steps: drop the release from RELEASES (here: the sign job's allow set) and add it to
        RETIRED_RELEASES / `retired`. The next builds publish no entry for it; its last file is allowed only as
        a carry-over of a recorded build; a manifest entry for it is refused."""
        text = sign_check_script().replace('"debian-11", "debian-12", "debian-13",', '"debian-11", "debian-13",')
        text = text.replace("retired = set()", 'retired = {"debian-12"}')
        script = os.path.join(self.repo, "retired-check.py")
        with open(script, "w") as handle:
            handle.write(text)
        self.assertIn("'debian-12' is not on the allowlist", self.run_check(script).stdout)
        entry = self.manifest["releases"]["debian-12"]
        with open(os.path.join(self.repo, "builds", "1.json"), "w") as handle:
            json.dump({"serial": 1, "manifest": self.manifest}, handle)
        retired = build.ReleaseOptions(builder=lambda site_v1, log, previous, today: ({}, {}, {}))
        manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, None, self.out_copy(),
                                  build.Log(echo=False), retired)
        self.manifest = manifest
        self.assertEqual(manifest["releases"], {})
        self.assertTrue(os.path.exists(os.path.join(self.out, "v1", entry["file"])), "carried over")
        result = self.run_check(script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def out_copy(self):
        live = os.path.join(self.repo, "live")
        shutil.copytree(self.out, live)
        return live

    def test_allowlist_matches_the_builder(self):
        text = open(WORKFLOW, encoding="utf-8").read()
        match = re.search(r"allow = \{([^}]*)\}", text)
        self.assertIsNotNone(match)
        self.assertEqual(set(re.findall(r'"([a-z0-9.-]+)"', match.group(1))), set(osvfeed.RELEASE_KEYS))

    def test_good_artifact_passes(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 release file(s) match the manifest", result.stdout)

    def test_tampered_release_file_refused(self):
        entry = self.manifest["releases"]["debian-12"]
        with open(os.path.join(self.out, "v1", entry["file"]), "ab") as handle:
            handle.write(b" ")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its sha256/bytes", result.stdout)

    def test_unlisted_release_and_stray_file_refused(self):
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        manifest["releases"]["debian-99"] = dict(manifest["releases"]["debian-12"])
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        with open(os.path.join(self.out, "v1", "r", "evil-0123456789abcdef.json"), "w") as handle:
            handle.write("{}")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("'debian-99' is not on the allowlist", result.stdout)
        self.assertIn("unexpected file v1/r/evil-0123456789abcdef.json", result.stdout)

    def edit_entry(self, key, change):
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        entry = manifest["releases"].setdefault(key, dict(manifest["releases"]["debian-12"]))
        change(entry)
        with open(path, "w") as handle:
            json.dump(manifest, handle)

    def test_eol_fields_checked(self):
        # S6: the build set debian-12's eol from builder/eol.py, and the check accepts it.
        self.assertEqual(self.manifest["releases"]["debian-12"]["eol"], "2028-06-30")
        cases = [
            ("debian-12", lambda e: e.update(eol="2028-02-30"), "eol is not a YYYY-MM-DD date"),
            ("debian-12", lambda e: e.update(eol="28-06-30"), "eol is not a YYYY-MM-DD date"),
            ("debian-12", lambda e: e.update(eol=20280630), "eol is not a YYYY-MM-DD date"),
            ("debian-12", lambda e: e.update(eolPro="2030-06-30"), "eolPro on a key that is not ubuntu-NN.NN"),
            ("ubuntu-24.04-esm", lambda e: e.update(eol="2029-05-31", eolPro="2034-04-25"),
             "eolPro on a key that is not ubuntu-NN.NN"),
            ("ubuntu-24.04", lambda e: e.update(eol="2029-05-31", eolPro="2029-05-30"),
             "eolPro without eol, or before it"),
            ("ubuntu-24.04", lambda e: (e.pop("eol"), e.update(eolPro="2034-04-25")),
             "eolPro without eol, or before it"),
            ("ubuntu-24.04", lambda e: e.update(eol="2029-05-31", eolPro="2034-04-31"),
             "eolPro is not a YYYY-MM-DD date"),
            ("debian-12", lambda e: e.update(eolDate="2028-06-30"), "bad entry keys"),
        ]
        for key, change, why in cases:
            with self.subTest(why=why, key=key):
                self.setUp()
                self.edit_entry(key, change)
                result = self.run_check()
                self.assertNotEqual(result.returncode, 0, why)
                self.assertIn(f"release {key}: {why}", result.stdout)

    def test_eol_problem_accepts(self):
        text = sign_check_script()
        namespace = {}
        exec("import datetime, re\n" + textwrap.dedent(text[text.index("entry_keys = "):text.index("# S5 review L7 / S6")]),
             namespace)
        problem = namespace["eol_problem"]
        for key, entry in (("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": "2034-04-25"}),
                           ("ubuntu-24.04", {"eol": "2029-05-31", "eolPro": "2029-05-31"}),
                           ("ubuntu-26.10", {"eol": "2027-07-15"}), ("debian-12", {}),
                           ("alpine-3.24", {"eol": "2028-06-01"}), ("ubuntu-24.04-esm", {})):
            self.assertIsNone(problem(key, entry), (key, entry))
        import eol
        for key in osvfeed.RELEASE_KEYS:
            self.assertIsNone(problem(key, eol.fields(key)), key)
            for name in ("eol", "eolPro"):      # the same verdicts as the builder's check_fields on bad values
                for value in ("2029-02-29", "2029-5-1", None):
                    entry = dict(eol.fields(key), **{name: value})
                    self.assertEqual(problem(key, entry) is None, eol.check_fields(key, entry) is None,
                                     (key, entry))

    def test_bad_sources_refused(self):
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        manifest["sources"]["osv"] = {"Ubuntu": "today"}
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sources.osv", result.stdout)


def alpine_releases():
    """ReleaseOptions whose S2 step writes one small, valid alpine-3.22 file and no dpkg release, so `sources`
    has an EMPTY archive (no network)."""
    from feedlib import content_name, sha256_hex
    release = next(r for r in osvfeed.RELEASES if r.key == "alpine-3.22")

    def builder(site_v1, log, previous, today):
        rows = [{"source": "openssl", "introduced": "0", "fixed": "3.3.2-r0", "severity": 3,
                 "ids": ["CVE-2024-1001"], "kernel": False, "date": None}]
        data = osvfeed.body_bytes(osvfeed.release_body(release, rows))
        name = "r/" + content_name("alpine-3.22", data)
        os.makedirs(os.path.join(site_v1, "r"), exist_ok=True)
        with open(os.path.join(site_v1, name), "wb") as handle:
            handle.write(data)
        return ({"alpine-3.22": {"format": "apk", "file": name, "sha256": sha256_hex(data), "bytes": len(data),
                                 "rows": 1}},
                {"osv": {"Alpine": "2026-11-05T09:30:02Z"}, "archive": {}, "baseline": {}}, {})
    return build.ReleaseOptions(builder=builder)


class SignJobFormats(unittest.TestCase):
    """L4: the sign job's format ties: alpine-* entries must be apk, a release body's `format` must equal its
    manifest entry's, and `sources.archive` may be empty only when every release is an Alpine one."""

    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")
        self.manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                       options=alpine_releases())
        self.script = os.path.join(self.repo, "signcheck.py")
        with open(self.script, "w") as handle:
            handle.write(sign_check_script())

    def run_check(self):
        env = dict(os.environ, SITE=self.out, SERIAL=str(self.manifest["serial"]), DATE=NOW[:10])
        return subprocess.run([sys.executable, "-I", self.script], cwd=self.repo, env=env, capture_output=True,
                              text=True)

    def edit_manifest(self, change):
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        change(manifest)
        with open(path, "w") as handle:
            json.dump(manifest, handle)

    def test_all_alpine_feed_with_an_empty_archive_passes(self):
        self.assertEqual(self.manifest["sources"]["archive"], {})
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 release file(s) match the manifest", result.stdout)

    def test_empty_archive_refused_with_a_dpkg_release(self):
        def add_dpkg(manifest):
            entry = dict(manifest["releases"]["alpine-3.22"])
            manifest["releases"]["debian-12"] = dict(entry, format="dpkg")
            manifest["sources"]["osv"]["Debian"] = "2026-11-05T09:30:02Z"
        self.edit_manifest(add_dpkg)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sources.archive is not {suite: UTC time}", result.stdout)

    def test_alpine_entry_must_be_apk(self):
        self.edit_manifest(lambda m: m["releases"]["alpine-3.22"].update(format="dpkg"))
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release alpine-3.22: bad entry", result.stdout)

    def test_body_format_must_equal_the_entry(self):
        # A body whose `format` disagrees with its (correct) entry: rewrite the file and re-pin its sha/name.
        import hashlib
        entry = self.manifest["releases"]["alpine-3.22"]
        path = os.path.join(self.out, "v1", entry["file"])
        with open(path, "rb") as handle:
            body = json.loads(handle.read())
        os.remove(path)
        body["format"] = "dpkg"
        data = osvfeed.body_bytes(body)
        sha = hashlib.sha256(data).hexdigest()
        name = f"r/alpine-3.22-{sha[:16]}.json"
        with open(os.path.join(self.out, "v1", name), "wb") as handle:
            handle.write(data)
        self.edit_manifest(lambda m: m["releases"]["alpine-3.22"].update(file=name, sha256=sha, bytes=len(data)))
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("says format 'dpkg', the manifest 'apk'", result.stdout)


class SignJobFixDates(unittest.TestCase):
    """S7c: a dpkg / apk package row may carry a 5th element, the fix's publish date: the sign job, inline, takes a
    real YYYY-MM-DD day or null (dpkg), null only (apk), and refuses anything else in that slot."""

    def build_site(self, options):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")
        self.manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                       options=options)
        self.script = os.path.join(self.repo, "signcheck.py")
        with open(self.script, "w") as handle:
            handle.write(sign_check_script())

    def check_with(self, options, key, change):
        import hashlib
        self.build_site(options)
        path = os.path.join(self.out, "v1", "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        entry = manifest["releases"][key]
        body_path = os.path.join(self.out, "v1", entry["file"])
        with open(body_path, "rb") as handle:
            body = json.loads(handle.read())
        os.remove(body_path)
        change(body)
        data = osvfeed.body_bytes(body)
        sha = hashlib.sha256(data).hexdigest()
        name = f"r/{key}-{sha[:16]}.json"
        with open(os.path.join(self.out, "v1", name), "wb") as handle:
            handle.write(data)
        entry.update(file=name, sha256=sha, bytes=len(data))
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        env = dict(os.environ, SITE=self.out, SERIAL=str(self.manifest["serial"]), DATE=NOW[:10])
        return subprocess.run([sys.executable, "-I", self.script], cwd=self.repo, env=env, capture_output=True,
                              text=True)

    def row(self, body):
        return next(iter(body["pkgs"].values()))[0]

    def test_dpkg(self):
        self.build_site(helpers.fake_releases())
        with open(os.path.join(self.out, "v1", self.manifest["releases"]["debian-12"]["file"]), "rb") as handle:
            self.assertEqual(json.loads(handle.read())["pkgs"]["apt"][0][4], "2026-11-04", "the builder dates it")
        why = "has a bad package row (not 4 fields, or a bad fix date)"
        for value in ("2026-13-01", "2026-02-30", "2026-11-4", "2026-11-04T00:00:00Z", "2026-11-04\n", "",
                      20261104, True, ["2026-11-04"], {"d": "2026-11-04"}):
            with self.subTest(value=value):
                result = self.check_with(helpers.fake_releases(), "debian-12",
                                         lambda b: self.row(b).__setitem__(4, value))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(why, result.stdout)
        for change in (lambda b: self.row(b).append(None), lambda b: (self.row(b).pop(), self.row(b).pop()),
                       lambda b: b["pkgs"].update(apt="x"),               # rows not a list
                       lambda b: b["pkgs"].update(apt=["0"])):             # a row that is not a list
            with self.subTest(change=change):
                result = self.check_with(helpers.fake_releases(), "debian-12", change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(why, result.stdout)
        for change in (lambda b: None, lambda b: self.row(b).__setitem__(4, None),
                       lambda b: self.row(b).__setitem__(4, "2024-02-29"), lambda b: self.row(b).pop()):
            with self.subTest(change=change):
                result = self.check_with(helpers.fake_releases(), "debian-12", change)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_apk_null_only(self):
        self.build_site(alpine_releases())
        with open(os.path.join(self.out, "v1", self.manifest["releases"]["alpine-3.22"]["file"]), "rb") as handle:
            self.assertEqual(json.loads(handle.read())["pkgs"]["openssl"][0][4:], [None])
        result = self.check_with(alpine_releases(), "alpine-3.22", lambda b: self.row(b).__setitem__(4, "2026-11-04"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has a bad package row (not 4 fields, or a bad fix date)", result.stdout)
        for change in (lambda b: None, lambda b: self.row(b).pop()):
            result = self.check_with(alpine_releases(), "alpine-3.22", change)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def rpm_releases():
    """ReleaseOptions whose S2 step writes one small, valid (compact) alma-9 file and nothing else."""
    from feedlib import content_name, sha256_hex
    release = next(r for r in osvfeed.RELEASES if r.key == "alma-9")

    def builder(site_v1, log, previous, today):
        rows = [{"source": "openssl-libs", "introduced": "0", "fixed": "1:3.5.8-2.el9_8", "severity": 3,
                 "ids": ["CVE-2026-10001"], "kernel": False, "date": "2026-10-01", "streams": []},
                {"source": "kernel-core", "introduced": "0", "fixed": "5.14.0-611.5.1.el9_8", "severity": 4,
                 "ids": ["CVE-2026-10002"], "kernel": True, "date": "2026-10-01"}]
        data = osvfeed.body_bytes(osvfeed.release_body(release, rows))
        name = "r/" + content_name("alma-9", data)
        os.makedirs(os.path.join(site_v1, "r"), exist_ok=True)
        with open(os.path.join(site_v1, name), "wb") as handle:
            handle.write(data)
        return ({"alma-9": {"format": "rpm", "file": name, "sha256": sha256_hex(data), "bytes": len(data),
                            "rows": 2}},
                {"osv": {"AlmaLinux": "2026-11-05T09:30:02Z"}, "archive": {}, "baseline": {}}, {})
    return build.ReleaseOptions(builder=builder)


class SignJobRpm(SignJobFormats):
    """S5: an rpm body carries `ids` and `fixes` too; alma-* / rhel-* entries must be rpm; an all-EL feed may have an
    empty archive."""

    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")
        self.manifest, _ = build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False),
                                       options=rpm_releases())
        self.script = os.path.join(self.repo, "signcheck.py")
        with open(self.script, "w") as handle:
            handle.write(sign_check_script())

    def test_all_alpine_feed_with_an_empty_archive_passes(self):
        self.assertEqual(self.manifest["sources"]["archive"], {})
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 release file(s) match the manifest", result.stdout)

    def test_empty_archive_refused_with_a_dpkg_release(self):
        def add_dpkg(manifest):
            manifest["releases"]["debian-12"] = dict(manifest["releases"]["alma-9"], format="dpkg")
        self.edit_manifest(add_dpkg)
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sources.archive is not {suite: UTC time}", result.stdout)

    def test_alpine_entry_must_be_apk(self):
        self.edit_manifest(lambda m: m["releases"]["alma-9"].update(format="dpkg"))
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release alma-9: bad entry", result.stdout)

    def test_body_format_must_equal_the_entry(self):
        import hashlib
        entry = self.manifest["releases"]["alma-9"]
        path = os.path.join(self.out, "v1", entry["file"])
        with open(path, "rb") as handle:
            body = json.loads(handle.read())
        os.remove(path)
        body["format"] = "apk"
        data = osvfeed.body_bytes(body)
        sha = hashlib.sha256(data).hexdigest()
        name = f"r/alma-9-{sha[:16]}.json"
        with open(os.path.join(self.out, "v1", name), "wb") as handle:
            handle.write(data)
        self.edit_manifest(lambda m: m["releases"]["alma-9"].update(file=name, sha256=sha, bytes=len(data)))
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("says format 'apk', the manifest 'rpm'", result.stdout)

    def test_rpm_body_without_its_tables_refused(self):
        import hashlib
        entry = self.manifest["releases"]["alma-9"]
        path = os.path.join(self.out, "v1", entry["file"])
        with open(path, "rb") as handle:
            body = json.loads(handle.read())
        os.remove(path)
        del body["fixes"]
        data = osvfeed.body_bytes(body)
        sha = hashlib.sha256(data).hexdigest()
        name = f"r/alma-9-{sha[:16]}.json"
        with open(os.path.join(self.out, "v1", name), "wb") as handle:
            handle.write(data)
        self.edit_manifest(lambda m: m["releases"]["alma-9"].update(file=name, sha256=sha, bytes=len(data)))
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not name its release", result.stdout)

    def rewrite_body(self, change):
        """Applies `change` to the alma-9 body and re-pins its file name, sha256 and bytes in the manifest."""
        import hashlib
        entry = self.manifest["releases"]["alma-9"]
        path = os.path.join(self.out, "v1", entry["file"])
        with open(path, "rb") as handle:
            body = json.loads(handle.read())
        os.remove(path)
        change(body)
        data = osvfeed.body_bytes(body)
        sha = hashlib.sha256(data).hexdigest()
        name = f"r/alma-9-{sha[:16]}.json"
        with open(os.path.join(self.out, "v1", name), "wb") as handle:
            handle.write(data)
        try:
            rows = sum(len(v) for part in ("pkgs", "kernel") for v in body[part].values())
        except (AttributeError, TypeError):
            rows = entry["rows"]
        self.edit_manifest(lambda m: m["releases"]["alma-9"].update(file=name, sha256=sha, bytes=len(data), rows=rows))

    def test_rpm_index_integrity(self):
        # L7: the compact tables' indexes, checked inline (the build job's check_release_body did the full schema).
        cases = [
            (lambda b: b["pkgs"].update({"openssl-libs": [1]}), "has a bad rpm pkgs fix indexes"),     # out of range
            (lambda b: b["pkgs"].update({"openssl-libs": []}), "has a bad rpm pkgs fix indexes"),
            (lambda b: b["pkgs"].update({"openssl-libs": ["0"]}), "has a bad rpm pkgs fix indexes"),
            (lambda b: b["pkgs"].update({"openssl-libs": [0, 0]}), "has a bad rpm pkgs fix indexes"),
            (lambda b: b["fixes"][0][3].append(5), "has a bad rpm fixes table"),
            (lambda b: (b["fixes"][0].pop(), b["fixes"][0].pop()), "has a bad rpm fixes table"),
            (lambda b: b["fixes"][0].append("x"), "has a bad rpm fixes table"),
            # S7c: the optional 6th element, the fix's publish date, is a real YYYY-MM-DD day or null.
            (lambda b: b["fixes"][0].__setitem__(5, "2026-13-01"), "has a bad rpm fix date"),
            (lambda b: b["fixes"][0].__setitem__(5, "2026-10-1"), "has a bad rpm fix date"),
            (lambda b: b["fixes"][0].__setitem__(5, "2026-10-01T00:00:00Z"), "has a bad rpm fix date"),
            (lambda b: b["fixes"][0].__setitem__(5, 20261001), "has a bad rpm fix date"),
            (lambda b: b["fixes"][0].__setitem__(5, ""), "has a bad rpm fix date"),
            (lambda b: b["fixes"].append(["0", "1:9-1.el9", 3, [0], []]),
             "has a bad rpm table (an id or a fix nothing refers to)"),
            (lambda b: b["ids"].append("CVE-2026-19999"), "has a bad rpm table (an id or a fix nothing refers to)"),
            (lambda b: b["ids"].insert(0, "RHSA-2026:1"), "has a bad rpm ids table"),
            (lambda b: b.update(ids={"CVE-2026-10001": 0}), "has a bad rpm ids table"),
            # S6 (S5 review LOW): severities High/Critical only, streams short strings, no kernel binary in pkgs,
            # kernel keys only RPM_KERNELS.
            (lambda b: b["fixes"][0].__setitem__(2, 2), "has a bad rpm fix severity or streams"),
            (lambda b: b["fixes"][0].__setitem__(2, "3"), "has a bad rpm fix severity or streams"),
            (lambda b: b["fixes"][0].__setitem__(2, 3.0), "has a bad rpm fix severity or streams"),
            (lambda b: b["fixes"][0].__setitem__(4, ["php:" + "8" * 61]), "has a bad rpm fix severity or streams"),
            (lambda b: b["fixes"][0].__setitem__(4, "php:8.1"), "has a bad rpm fix severity or streams"),
            (lambda b: b["fixes"][0].__setitem__(4, [81]), "has a bad rpm fix severity or streams"),
            (lambda b: b["pkgs"].update({"kernel-modules": b["pkgs"]["openssl-libs"]}),
             "has a bad rpm pkgs binary (a kernel binary)"),
            (lambda b: b["pkgs"].update({"kernel": b["pkgs"]["openssl-libs"]}),
             "has a bad rpm pkgs binary (a kernel binary)"),
            (lambda b: b["pkgs"].update({"perf": b["pkgs"]["openssl-libs"]}),
             "has a bad rpm pkgs binary (a kernel binary)"),
            (lambda b: b["kernel"].update({"kernel-modules": b["kernel"].pop("kernel-core")}),
             "has a bad rpm kernel binary (not one of RPM_KERNELS)"),
            (lambda b: b["kernel"].update({"kernel": b["kernel"].pop("kernel-core")}),
             "has a bad rpm kernel binary (not one of RPM_KERNELS)"),
        ]
        for change, why in cases:
            with self.subTest(why=why):
                self.setUp()
                self.rewrite_body(change)
                result = self.run_check()
                self.assertNotEqual(result.returncode, 0, why)
                self.assertIn(why, result.stdout)
        for change in (lambda b: None, lambda b: b["fixes"][0].__setitem__(2, 4),
                       lambda b: b["fixes"][0].__setitem__(4, ["php:" + "8" * 60]),
                       lambda b: b["kernel"].update({"kernel-rt-core": b["kernel"].pop("kernel-core")}),
                       lambda b: b["fixes"][0].pop(), lambda b: b["fixes"][0].__setitem__(5, None)):
            self.setUp()
            self.rewrite_body(change)
            result = self.run_check()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_kernel_sets_match_the_builder(self):
        text = sign_check_script()
        for name, want in (("rpm_kernels", osvfeed.RPM_KERNELS), ("rpm_kernel_userspace", osvfeed.RPM_KERNEL_USERSPACE)):
            match = re.search(name + r" = \{([^}]*)\}", text)
            self.assertIsNotNone(match, name)
            self.assertEqual(set(re.findall(r'"([A-Za-z0-9.+-]+)"', match.group(1))), set(want), name)

    def test_rhel_keys_are_rpm(self):
        text = sign_check_script()
        namespace = {}
        exec(text[text.index("def fmt_of"):text.index("iso = re.compile")].replace("          ", ""), namespace)
        self.assertEqual([namespace["fmt_of"](k) for k in ("alma-8", "rhel-10", "alpine-3.20", "debian-12")],
                         ["rpm", "rpm", "apk", "dpkg"])


if __name__ == "__main__":
    unittest.main()
