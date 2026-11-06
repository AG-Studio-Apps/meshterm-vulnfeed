"""builder/apkver.py against apk-tools' own vectors (tests/fixtures/apk-version.data, shared byte for byte with
meshTerm's ApkVersion), run the way apk-tools test/unit/version_test.c runs them."""
import hashlib
import os
import unittest

import helpers
import apkver

DATA = os.path.join(helpers.ROOT, "tests", "fixtures", "apk-version.data")
# The shared copy (header + upstream bytes). Changing it means changing meshTerm's copy in the same breath.
DATA_SHA256 = "75ff1e3e94ee8fece67756b058af2c33761352e02a8913d45540d7657aa342c2"
UPSTREAM_SHA256 = "daa0a0cd6ec90f42769398e9d01516d3665b61f37046a5dfd9cd7464982542b6"


def one_line(arg):
    """version_test_one(): (ok, is a check). Comments and surrounding whitespace are trimmed; a blank line is
    no check."""
    arg = arg.split("#", 1)[0].strip()
    if not arg:
        return True, False
    if " " in arg and " " in arg.split(" ", 1)[1]:
        ver1, rest = arg.split(" ", 1)
        op, ver2 = rest.split(" ", 1)
        invert = op.startswith("!")
        if invert:
            op = op[1:]
        ok = apkver.match(ver1, apkver.result_mask(op), ver2)
    else:
        ver1 = arg
        invert = ver1.startswith("!")
        if invert:
            ver1 = ver1[1:]
        ok = apkver.validate(ver1)
    return (not ok) if invert else ok, True


class SharedVectors(unittest.TestCase):
    def read(self):
        with open(DATA, "rb") as handle:
            return handle.read()

    def test_copy_is_pinned(self):
        raw = self.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), DATA_SHA256, "the shared copy drifted")
        lines = raw.split(b"\n")
        header = 0
        while lines[header].startswith(b"#"):
            header += 1
        self.assertEqual(header, 7)
        self.assertIn(UPSTREAM_SHA256.encode(), b"\n".join(lines[:header]))
        self.assertEqual(hashlib.sha256(b"\n".join(lines[header:])).hexdigest(), UPSTREAM_SHA256,
                         "the body after the header is not apk-tools v3.0.8 test/unit/version.data")

    def test_every_vector(self):
        failures, checks = [], 0
        for line in self.read().decode("utf-8").split("\n"):
            ok, counted = one_line(line)
            checks += counted
            if not ok:
                failures.append(line)
        self.assertEqual(failures, [])
        # 788 upstream lines: 754 comparisons, 31 validity checks, 3 blank (the 7 header lines are comments).
        self.assertEqual(checks, 785)


class Semantics(unittest.TestCase):
    def test_order(self):
        chain = ["1.0_alpha", "1.0_alpha1", "1.0_beta", "1.0_pre", "1.0_rc1", "1.0", "1.0-r1", "1.0_cvs",
                 "1.0_p1", "1.0a", "1.0.1", "1.1"]
        self.assertEqual(sorted(reversed(chain), key=apkver.sort_key), chain)
        self.assertEqual(apkver.compare("1.01", "1.1"), -1, "a leading zero compares as bytes")
        # An upstream-only `introduced` (OSV Alpine's 2.9.2) is below every packaged 2.9.2-rN.
        self.assertEqual(apkver.compare("2.9.2", "2.9.2-r0"), -1)
        self.assertEqual(apkver.compare("2.9.2", "2.9.2-r1"), -1)
        self.assertEqual(apkver.compare("3.3.2-r0", "3.3.10-r0"), -1)

    def test_validate(self):
        for good in ("1", "3.3.2-r0", "20190514a-r0", "1.2_rc1_p2~deadbeef-r3", "2.9.2"):
            self.assertTrue(apkver.validate(good), good)
        for bad in ("", "a1", "1.0-r", "1-x", "1.0ab", "1..2", "1.0_foo", "1~", "1-r1.2", "1999-12-14",
                    "1.0 ", "v1.0", "1.0-r1-r2"):
            self.assertFalse(apkver.validate(bad), bad)

    def test_uint64_wraps(self):
        self.assertEqual(apkver.compare("18446744073709551616", "0"), 0, "2**64 wraps to 0")
        self.assertEqual(apkver.compare("18446744073709551617", "1"), 0)

    def test_fuzzy(self):
        self.assertTrue(apkver.match("1.2.3", apkver.result_mask("~"), "1.2"))
        self.assertFalse(apkver.match("1.3", apkver.result_mask("~"), "1.2"))


if __name__ == "__main__":
    unittest.main()
