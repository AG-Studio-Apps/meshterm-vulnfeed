import functools
import os
import unittest

import helpers  # noqa: F401  (sys.path)
from dpkgver import DpkgVersion, VersionError, compare, is_valid, verrevcmp

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def sign(n):
    return (n > 0) - (n < 0)


class DpkgUpstreamCases(unittest.TestCase):
    """dpkg's own scripts/t/Dpkg_Version.t comparison table, in both directions."""

    def test_table(self):
        cases = 0
        with open(os.path.join(FIXTURES, "dpkg-version-cases.txt")) as handle:
            for line in handle:
                if not line.strip() or line.startswith("#"):
                    continue
                a, b, want = line.split()
                cases += 1
                with self.subTest(a=a, b=b):
                    self.assertEqual(compare(a, b), int(want))
                    self.assertEqual(compare(b, a), -int(want))
        self.assertEqual(cases, 43)

    def test_dpkg_sort_lists(self):
        # The three sorted lists at the end of Dpkg_Version.t.
        unsorted = ["4:4-4", "5.0abc", "0.0-0.0alpha0", "10.100.1-1", "0~999.999zeta", "0:1.0-0"]
        self.assertEqual(sorted(unsorted, key=functools.cmp_to_key(compare)),
                         ["0~999.999zeta", "0.0-0.0alpha0", "0:1.0-0", "5.0abc", "10.100.1-1", "4:4-4"])
        parts = ["4", "5.0abc", "0.0alpha0", "10.100.1", "0~999.999zeta", "1.0"]
        self.assertEqual(sorted(parts, key=functools.cmp_to_key(verrevcmp)),
                         ["0~999.999zeta", "0.0alpha0", "1.0", "4", "5.0abc", "10.100.1"])
        strings = ["10a10", "~zyx999", "Z0z", "~000", "aa5AA", "~abc"]
        # version_compare_string is verrevcmp over a string with no digits treated specially beyond policy.
        self.assertEqual(sorted(strings, key=functools.cmp_to_key(verrevcmp)),
                         ["~000", "~abc", "~zyx999", "10a10", "Z0z", "aa5AA"])

    def test_dpkg_validity_cases(self):
        # Dpkg_Version.t and lib/dpkg/t/t-version.c parse cases.
        for bad in ("", "  ", "-0", "0:-0", ":1.0", "1.0-", "10a:5.2", "5.2@3-2", "foo5.2", "0:foo5.2", "0:",
                    "0:0 0-1", "-1:0-1", "999999999999999999999999:0-1", "a:0-0", "A:0-0", "0:abc3-0",
                    "0:0-0:0"):
            with self.subTest(bad=bad):
                self.assertFalse(is_valid(bad))
        for char in "!#@$%&/|\\<>()[]{};,_=*^'":
            self.assertFalse(is_valid(f"0:0{char}-0"), char)
            self.assertFalse(is_valid(f"0:0-0{char}"), char)
        for good in ("0", "0:0", "0:0-0", "0:0.0-0.0", "1:0", "5:1", "0:0-0-0", "0:0-0-0-0", "0:0:0-0",
                     "0:0:0:0-0", "0:0:0-0-0", "0:0-0:0-0", "0:09azAZ.-+~:-0", "0:0-azAZ09.+~", "  \t0:0-1",
                     "0:0-1\t  ", "1:1.0:1.0", "1.0-1.0-1"):
            with self.subTest(good=good):
                self.assertTrue(is_valid(good))

    def test_parse_parts(self):
        v = DpkgVersion.parse("0:0:0-0-0")
        self.assertEqual((v.epoch, v.upstream, v.revision), (0, "0:0-0", "0"))
        v = DpkgVersion.parse("1.0-1.0-1")
        self.assertEqual((v.epoch, v.upstream, v.revision), (0, "1.0-1.0", "1"))
        v = DpkgVersion.parse("5:1")
        self.assertEqual((v.epoch, v.upstream, v.revision), (5, "1", ""))
        with self.assertRaises(VersionError):
            DpkgVersion.parse("1.0-")


class PolicyCases(unittest.TestCase):
    """Debian Policy 5.6.12 and the distro versions the feed actually compares."""

    def test_tilde_sorts_before_everything(self):
        self.assertLess(DpkgVersion.parse("1.0~rc1"), DpkgVersion.parse("1.0"))
        self.assertLess(DpkgVersion.parse("1.0~~"), DpkgVersion.parse("1.0~"))
        self.assertLess(DpkgVersion.parse("6.8.0-1040.42~22.04.1"), DpkgVersion.parse("6.8.0-1040.42"))

    def test_letters_before_non_letters(self):
        self.assertLess(DpkgVersion.parse("1.0a"), DpkgVersion.parse("1.0+"))
        self.assertLess(DpkgVersion.parse("1.0+b1"), DpkgVersion.parse("1.0.1"))

    def test_epoch_wins(self):
        self.assertGreater(DpkgVersion.parse("1:1.0"), DpkgVersion.parse("9.9"))
        self.assertEqual(DpkgVersion.parse("0:1.0"), DpkgVersion.parse("1.0"))

    def test_absent_revision_equals_zero(self):
        self.assertEqual(DpkgVersion.parse("1.0"), DpkgVersion.parse("1.0-0"))

    def test_backports(self):
        self.assertGreater(DpkgVersion.parse("1:9.6p1-3ubuntu13.20"), DpkgVersion.parse("1:9.6p1-3ubuntu13.3"))
        self.assertLess(DpkgVersion.parse("252.23-1~deb12u1"), DpkgVersion.parse("252.23-1"))
        self.assertGreater(DpkgVersion.parse("252.23-1~deb12u1"), DpkgVersion.parse("252.6-1"))
        self.assertLess(DpkgVersion.parse("2.36-9"), DpkgVersion.parse("2.36-9+deb12u14"))
        self.assertLess(DpkgVersion.parse("5.4.1-0.2"), DpkgVersion.parse("5.4.1-1"))
        self.assertLess(DpkgVersion.parse("3.0.13-0ubuntu3.5"), DpkgVersion.parse("3.0.13-0ubuntu3.16"))

    def test_date_is_a_valid_version_but_not_a_fix(self):
        # The UBUNTU-CVE-2024-6716 tiff value parses as a Debian version (upstream 2024-08, revision 16):
        # the builder rejects it by shape, not by parse.
        self.assertTrue(is_valid("2024-08-16"))

    def test_not_hashable(self):
        with self.assertRaises(TypeError):
            hash(DpkgVersion.parse("1.0"))


if __name__ == "__main__":
    unittest.main()
