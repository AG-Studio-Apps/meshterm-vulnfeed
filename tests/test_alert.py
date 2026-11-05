import contextlib
import datetime
import functools
import http.server
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest

import helpers
import build
import check
import sign

check.RETRY_DELAY = 0

GENERATED = "2026-11-05T05:10:00Z"
FRESH = datetime.datetime(2026, 11, 5, 7, 0, tzinfo=datetime.timezone.utc)
STALE = datetime.datetime(2026, 11, 6, 6, 0, tzinfo=datetime.timezone.utc)


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class FakeGh:
    """Records gh calls; `issues` is what `gh issue list` returns."""

    def __init__(self, issues=None, fail=False):
        self.calls, self.issues, self.fail = [], issues or [], fail

    def __call__(self, args):
        self.calls.append(args)
        if self.fail:
            return subprocess.CompletedProcess(args, 1, "", "HTTP 401")
        out = json.dumps(self.issues) if args[:2] == ["issue", "list"] else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    def verbs(self):
        return [" ".join(c[:2]) for c in self.calls]


class AlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vulnfeed-alert-")
        cls.feed_key, cls.feed_pub = helpers.make_key(cls.tmp, "feed")
        cls.em_key, cls.em_pub = helpers.make_key(cls.tmp, "emergency")
        cls.other_key, _ = helpers.make_key(cls.tmp, "other")
        cls.keys = helpers.make_keys_dir(cls.tmp, cls.feed_pub, cls.em_pub)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.repo = helpers.scratch_repo()
        self.addCleanup(shutil.rmtree, self.repo)
        self.site = os.path.join(self.repo, "out")
        build.build(self.repo, self.site, helpers.COMMIT, GENERATED, log=build.Log(echo=False),
                    options=helpers.no_releases())
        self.manifest = os.path.join(self.site, "v1", "manifest.json")

    def sign_with(self, key, role="feed"):
        sig = self.manifest + ".minisig"
        if os.path.exists(sig):
            os.unlink(sig)
        comment = sign.trusted_comment(1, GENERATED[:10], helpers.COMMIT)
        subprocess.run(["minisign", "-S", "-s", key, "-m", self.manifest, "-x", sig, "-t", comment],
                       check=True, capture_output=True)

    def serve(self):
        handler = functools.partial(Quiet, directory=self.site)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def kinds(self, result):
        return [p["kind"] for p in result["problems"]]

    # --- evaluate ---------------------------------------------------------------------------------------
    def test_fresh_and_verified_is_ok_over_http(self):
        self.sign_with(self.feed_key)
        result = check.evaluate(self.serve(), self.keys, FRESH)
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["serial"], result["signer"]), (1, "feed"))

    def test_file_url_works(self):
        self.sign_with(self.feed_key)
        result = check.evaluate("file://" + self.site, self.keys, FRESH)
        self.assertTrue(result["ok"], result)

    def test_stale_is_a_problem(self):
        self.sign_with(self.feed_key)
        result = check.evaluate(self.serve(), self.keys, STALE)
        self.assertEqual(self.kinds(result), ["stale"])
        self.assertFalse(result["ok"])

    def test_wrong_key_is_a_problem(self):
        self.sign_with(self.other_key)
        self.assertEqual(self.kinds(check.evaluate(self.serve(), self.keys, FRESH)), ["verify"])

    def test_emergency_key_is_flagged(self):
        self.sign_with(self.em_key)
        self.assertEqual(self.kinds(check.evaluate(self.serve(), self.keys, FRESH)), ["emergency-key"])

    def test_missing_signature_is_a_problem(self):
        self.assertEqual(self.kinds(check.evaluate(self.serve(), self.keys, FRESH)), ["fetch-signature"])

    def test_tampered_manifest_is_a_problem(self):
        self.sign_with(self.feed_key)
        with open(self.manifest, "ab") as handle:
            handle.write(b" ")
        self.assertEqual(self.kinds(check.evaluate(self.serve(), self.keys, FRESH)), ["verify"])

    def test_tampered_curated_is_a_problem(self):
        self.sign_with(self.feed_key)
        with open(self.manifest) as handle:
            name = json.load(handle)["curated"]["file"]
        with open(os.path.join(self.site, "v1", name), "ab") as handle:
            handle.write(b" ")
        self.assertEqual(self.kinds(check.evaluate(self.serve(), self.keys, FRESH)), ["curated-sha256"])

    def test_missing_site_is_a_problem(self):
        url = self.serve()
        shutil.rmtree(self.site)
        self.assertEqual(self.kinds(check.evaluate(url, self.keys, FRESH)), ["fetch-manifest"])

    def test_connection_refused_is_a_problem(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertEqual(self.kinds(check.evaluate(f"http://127.0.0.1:{port}", self.keys, FRESH)),
                         ["fetch-manifest"])

    def write_record(self, stale):
        records = os.path.join(self.repo, "records")
        os.makedirs(records, exist_ok=True)
        with open(os.path.join(records, "1.json"), "w") as handle:
            json.dump({"serial": 1, "stale": stale}, handle)
        return "file://" + records

    def test_release_stale_over_48_hours_is_its_own_problem(self):
        self.sign_with(self.feed_key)
        recent = self.write_record({"debian-12": {"since": "2026-11-04T17:10:00Z", "reason": "archive: 503"}})
        result = check.evaluate("file://" + self.site, self.keys, FRESH, record_url=recent)
        self.assertEqual(self.kinds(result), [])
        self.assertEqual(result["stale_releases"], ["debian-12"])
        old = self.write_record({"debian-12": {"since": "2026-11-03T05:10:00Z", "reason": "archive: 503"}})
        result = check.evaluate("file://" + self.site, self.keys, FRESH, record_url=old)
        self.assertEqual(self.kinds(result), ["stale-release"])
        self.assertIn("debian-12 since 2026-11-03T05:10:00Z", result["problems"][0]["detail"])

    def test_builder_bug_is_raised_at_once(self):
        self.sign_with(self.feed_key)
        url = self.write_record({"debian-12": {"since": "2026-11-05T05:10:00Z", "bug": True,
                                               "reason": "bug: build: KeyError: 'rows'", "traceback": "..."}})
        result = check.evaluate("file://" + self.site, self.keys, FRESH, record_url=url)
        self.assertEqual(self.kinds(result), ["builder-bug"])
        self.assertIn("debian-12", result["problems"][0]["detail"])

    def test_missing_record_is_a_problem(self):
        self.sign_with(self.feed_key)
        result = check.evaluate("file://" + self.site, self.keys, FRESH,
                                record_url="file://" + os.path.join(self.repo, "nowhere"))
        self.assertEqual(self.kinds(result), ["fetch-record"])

    def test_record_check_skipped_without_a_record_url(self):
        self.sign_with(self.feed_key)
        self.assertEqual(self.kinds(check.evaluate("file://" + self.site, self.keys, FRESH)), [])

    def test_one_blip_is_retried(self):
        calls = []
        real = check._fetch_once

        def flaky(url, cap):
            calls.append(url)
            if len(calls) == 1:
                raise check.FeedError("blip", transient=True)
            return real(url, cap)
        self.sign_with(self.feed_key)
        url = self.serve()
        check._fetch_once = flaky
        try:
            self.assertEqual(self.kinds(check.evaluate(url, self.keys, FRESH)), [])
        finally:
            check._fetch_once = real

    def test_incomplete_read_is_caught(self):
        import http.client
        class R:  # a response whose read() raises IncompleteRead (not an OSError)
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): raise http.client.IncompleteRead(b"x")
        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: R()
        try:
            with self.assertRaises(check.FeedError) as ctx:
                check._fetch_once("http://example.invalid/x", 10)
            self.assertTrue(ctx.exception.transient)
        finally:
            urllib.request.urlopen = orig

    # --- issue handling ---------------------------------------------------------------------------------
    def problem_result(self):
        return check.evaluate("file://" + self.site, self.keys, FRESH)  # unsigned: fetch-signature

    def test_files_a_new_issue_with_the_label(self):
        gh, state = FakeGh(), {}
        action = check.act(self.problem_result(), check.Gh("o/r", False, gh), state, FRESH, out=lambda *_: None)
        self.assertEqual(action, "filed")
        create = gh.calls[-1]
        self.assertEqual(create[:2], ["issue", "create"])
        self.assertIn("vulnfeed", create[create.index("--label") + 1])
        self.assertEqual(create[create.index("--title") + 1], check.TITLE)
        self.assertEqual(create[-2:], ["--repo", "o/r"])

    def test_same_problem_does_not_recomment(self):
        gh = FakeGh([{"number": 7, "title": check.TITLE}])
        state = {"fingerprint": "fetch-signature", "commented": check._iso(FRESH)}
        action = check.act(self.problem_result(), check.Gh("o/r", False, gh), state, FRESH)
        self.assertEqual(action, "unchanged #7")
        self.assertEqual(gh.verbs(), ["issue list"])

    def test_changed_or_overdue_problem_refreshes(self):
        gh = FakeGh([{"number": 7, "title": check.TITLE}])
        state = {"fingerprint": "stale", "commented": check._iso(FRESH)}
        self.assertEqual(check.act(self.problem_result(), check.Gh("o/r", False, gh), state, FRESH),
                         "refreshed #7")
        gh = FakeGh([{"number": 7, "title": check.TITLE}])
        state = {"fingerprint": "fetch-signature", "commented": "2026-11-03T00:00:00Z"}
        self.assertEqual(check.act(self.problem_result(), check.Gh("o/r", False, gh), state, FRESH),
                         "refreshed #7")
        self.assertEqual(gh.verbs(), ["issue list", "issue comment"])

    def test_recovery_closes_the_issue(self):
        self.sign_with(self.feed_key)
        ok = check.evaluate("file://" + self.site, self.keys, FRESH)
        gh = FakeGh([{"number": 9, "title": "something else"}, {"number": 7, "title": check.TITLE}])
        state = {"fingerprint": "stale"}
        self.assertEqual(check.act(ok, check.Gh("o/r", False, gh), state, FRESH), "closed #7")
        self.assertEqual(gh.verbs(), ["issue list", "issue comment", "issue close"])
        self.assertEqual(gh.calls[-1][2], "7")
        self.assertNotIn("fingerprint", state)

    def test_healthy_with_no_issue_does_nothing(self):
        self.sign_with(self.feed_key)
        ok = check.evaluate("file://" + self.site, self.keys, FRESH)
        gh = FakeGh()
        self.assertEqual(check.act(ok, check.Gh("o/r", False, gh), {}, FRESH), "healthy")
        self.assertEqual(gh.verbs(), ["issue list"])

    def test_dry_run_never_mutates(self):
        gh = FakeGh()
        printed = []
        action = check.act(self.problem_result(), check.Gh("o/r", True, gh, out=printed.append), {}, FRESH,
                           out=printed.append)
        self.assertEqual(action, "filed")
        self.assertEqual(gh.verbs(), ["issue list"])
        self.assertTrue(any("(dry-run) gh issue create" in p for p in printed))

    def test_main_defaults_to_dry_run(self):
        state_dir = os.path.join(self.repo, "state")
        env = {"VULNFEED_ALERT_URL": "file://" + self.site, "VULNFEED_ALERT_KEYS_DIR": self.keys,
               "VULNFEED_ALERT_STATE": state_dir}
        saved = {k: os.environ.get(k) for k in list(env) + ["VULNFEED_ALERT_DRY_RUN"]}
        os.environ.update(env)
        os.environ.pop("VULNFEED_ALERT_DRY_RUN", None)
        try:
            gh = FakeGh(fail=True)  # even a gh that cannot list is fine in a dry run
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(check.main(["run"], runner=gh, now=FRESH), 0)
            self.assertIn("dry_run=1", out.getvalue())
            self.assertEqual(gh.verbs(), ["issue list"])
            self.assertFalse(os.path.exists(os.path.join(state_dir, "state.json")))
            os.environ["VULNFEED_ALERT_DRY_RUN"] = "0"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(check.main(["run"], runner=FakeGh(fail=True), now=FRESH), 1)
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


class UnitFileTests(unittest.TestCase):
    def test_service_path_and_dry_run(self):
        with open(os.path.join(helpers.ROOT, "alert", "systemd", "vulnfeed-freshness.service")) as handle:
            unit = handle.read()
        path_line = next(line for line in unit.splitlines() if line.startswith("Environment=PATH="))
        self.assertIn("/home/linuxbrew/.linuxbrew/bin", path_line)
        self.assertIn("Environment=VULNFEED_ALERT_DRY_RUN=1", unit)
        self.assertIn("ExecStart=%h/.local/lib/vulnfeed-freshness/run.sh", unit)


if __name__ == "__main__":
    unittest.main()
