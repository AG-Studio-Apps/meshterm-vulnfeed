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
        text = sign_check_script().replace('"debian-11", "debian-12", "debian-13"}', '"debian-11", "debian-13"}')
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


if __name__ == "__main__":
    unittest.main()
