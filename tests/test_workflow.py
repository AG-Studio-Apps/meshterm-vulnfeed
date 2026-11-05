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

    def run_check(self):
        env = dict(os.environ, SITE=self.out, SERIAL=str(self.manifest["serial"]), DATE=NOW[:10])
        return subprocess.run([sys.executable, "-I", self.script], cwd=self.repo, env=env,
                              capture_output=True, text=True)

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
