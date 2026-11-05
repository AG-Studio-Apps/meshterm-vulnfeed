import contextlib
import io
import os
import re
import shutil
import tempfile
import unittest

import helpers
import build
import sign
from feedlib import COMMENT_RE, FeedError, key_id_of_pub

NOW = "2026-11-05T05:10:00Z"


class SignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vulnfeed-sign-")
        cls.feed_key, cls.feed_pub = helpers.make_key(cls.tmp, "feed")
        cls.em_key, cls.em_pub = helpers.make_key(cls.tmp, "emergency")
        cls.other_key, cls.other_pub = helpers.make_key(cls.tmp, "other")
        cls.keys = helpers.make_keys_dir(cls.tmp, cls.feed_pub, cls.em_pub)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.out = os.path.join(self.repo, "out")
        build.build(self.repo, self.out, helpers.COMMIT, NOW, log=build.Log(echo=False))
        self.manifest = os.path.join(self.out, "v1", "manifest.json")

    def read(self, path):
        with open(path, "rb") as handle:
            return handle.read()

    def test_trusted_comment_format(self):
        path, comment = sign.sign(self.manifest, self.feed_key, helpers.COMMIT, keys_dir=self.keys)
        self.assertEqual(comment, f"vulnfeed=host-vulns version=1 date=2026-11-05 commit={helpers.COMMIT}")
        self.assertEqual(self.read(path).decode().splitlines()[2], f"trusted comment: {comment}")
        tokens = comment.split(" ")
        self.assertEqual(tokens[0], "vulnfeed=host-vulns")
        self.assertTrue(tokens[1].startswith("version="), "version= must be the second token (app contract)")
        self.assertRegex(comment, COMMENT_RE)

    def test_verify_good_pair(self):
        sign.sign(self.manifest, self.feed_key, helpers.COMMIT, keys_dir=self.keys)
        role, serial, _ = sign.check_pair(self.read(self.manifest), self.read(self.manifest + ".minisig"),
                                          "feed", self.keys, require_commit=True)
        self.assertEqual((role, serial), ("feed", 1))

    def test_emergency_key_verifies_as_emergency_only(self):
        sign.sign(self.manifest, self.em_key, None, role="emergency", keys_dir=self.keys)
        body, sig = self.read(self.manifest), self.read(self.manifest + ".minisig")
        self.assertEqual(sign.check_pair(body, sig, "any", self.keys)[0], "emergency")
        with self.assertRaisesRegex(FeedError, "expected the feed key"):
            sign.check_pair(body, sig, "feed", self.keys)
        with self.assertRaisesRegex(FeedError, "no commit"):
            sign.check_pair(body, sig, "any", self.keys, require_commit=True)

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(FeedError, "not in keys/"):
            sign.sign(self.manifest, self.other_key, helpers.COMMIT, keys_dir=self.keys)
        self.assertFalse(os.path.exists(self.manifest + ".minisig"), "a failed sign leaves no signature")

    def test_wrong_key_with_spoofed_id_rejected(self):
        # A roster whose feed .pub carries another key's bytes under the signer's id fails in minisign itself.
        sign.sign(self.manifest, self.feed_key, helpers.COMMIT, keys_dir=self.keys)
        sig = self.read(self.manifest + ".minisig")
        spoof = tempfile.mkdtemp(prefix="vulnfeed-spoof-")
        self.addCleanup(shutil.rmtree, spoof)
        import base64
        real = base64.b64decode(self.read(self.feed_pub).decode().splitlines()[1])
        other = base64.b64decode(self.read(self.other_pub).decode().splitlines()[1])
        forged = real[:10] + other[10:]
        os.makedirs(os.path.join(spoof, "keys"))
        with open(os.path.join(spoof, "keys", "vulnfeed-feed.pub"), "w") as handle:
            handle.write("untrusted comment: forged\n" + base64.b64encode(forged).decode() + "\n")
        with self.assertRaisesRegex(FeedError, "does not verify"):
            sign.check_pair(self.read(self.manifest), sig, "any", os.path.join(spoof, "keys"))

    def test_tampered_body_rejected(self):
        sign.sign(self.manifest, self.feed_key, helpers.COMMIT, keys_dir=self.keys)
        body = self.read(self.manifest).replace(b'"serial": 1', b'"serial": 1 ')
        with self.assertRaisesRegex(FeedError, "does not verify"):
            sign.check_pair(body, self.read(self.manifest + ".minisig"), "any", self.keys)

    def test_recipes_style_comment_rejected(self):
        sig = self.manifest + ".minisig"
        import subprocess
        subprocess.run(["minisign", "-S", "-s", self.feed_key, "-m", self.manifest, "-x", sig,
                        "-t", "recipes=host-recipes version=1 date=2026-11-05"], check=True, capture_output=True)
        with self.assertRaisesRegex(FeedError, "trusted comment"):
            sign.check_pair(self.read(self.manifest), self.read(sig), "any", self.keys)

    def test_version_not_second_token_rejected(self):
        sig = self.manifest + ".minisig"
        import subprocess
        subprocess.run(["minisign", "-S", "-s", self.feed_key, "-m", self.manifest, "-x", sig,
                        "-t", "vulnfeed=host-vulns date=2026-11-05 version=1"], check=True, capture_output=True)
        with self.assertRaisesRegex(FeedError, "trusted comment"):
            sign.check_pair(self.read(self.manifest), self.read(sig), "any", self.keys)

    def test_serial_mismatch_rejected(self):
        sig = self.manifest + ".minisig"
        import subprocess
        subprocess.run(["minisign", "-S", "-s", self.feed_key, "-m", self.manifest, "-x", sig,
                        "-t", "vulnfeed=host-vulns version=2 date=2026-11-05"], check=True, capture_output=True)
        with self.assertRaisesRegex(FeedError, "serial"):
            sign.check_pair(self.read(self.manifest), self.read(sig), "any", self.keys)

    def test_cli_verify_exit_codes(self):
        sign.sign(self.manifest, self.feed_key, helpers.COMMIT, keys_dir=self.keys)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sign.main(["verify", "--manifest", self.manifest, "--keys-dir", self.keys]), 0)
            self.assertEqual(sign.main(["verify", "--manifest", self.manifest, "--keys-dir", self.keys,
                                        "--role", "emergency"]), 1)


class CommittedKeysTests(unittest.TestCase):
    """The committed public keys, their ids in keys/README.md, and the ids the workflow pins agree."""

    def test_ids(self):
        keys = os.path.join(helpers.ROOT, "keys")
        ids = {}
        for role in ("feed", "emergency"):
            with open(os.path.join(keys, f"vulnfeed-{role}.pub")) as handle:
                ids[role] = key_id_of_pub(handle.read())
        self.assertNotEqual(ids["feed"], ids["emergency"])
        with open(os.path.join(keys, "README.md")) as handle:
            readme = handle.read()
        with open(os.path.join(helpers.ROOT, ".github", "workflows", "build.yml")) as handle:
            workflow = handle.read()
        for role, kid in ids.items():
            self.assertIn(kid, readme)
        self.assertRegex(workflow, rf"FEED_KEY_ID: {ids['feed']}\b")
        self.assertRegex(workflow, rf"EMERGENCY_KEY_ID: {ids['emergency']}\b")
        self.assertEqual(sign.roster(keys)["feed"][1], ids["feed"])

    def test_no_secret_key_in_repo(self):
        for root, _, files in os.walk(helpers.ROOT):
            if "/.git" in root:
                continue
            for name in files:
                if name.endswith((".key", ".password")):
                    self.fail(f"secret-looking file in the repository: {os.path.join(root, name)}")
                path = os.path.join(root, name)
                with open(path, "rb") as handle:
                    head = handle.read(200)
                self.assertFalse(re.search(rb"minisign encrypted secret key", head), path)


if __name__ == "__main__":
    unittest.main()
