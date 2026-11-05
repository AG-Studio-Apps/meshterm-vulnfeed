"""builder/rpmver.py against rpm's own vectors (tests/fixtures/rpm-vercmp.at, shared byte for byte with meshTerm's
RpmVersion), plus the EVR rules (epoch, release) the feed adds on top of rpmvercmp."""
import hashlib
import os
import re
import unittest

import helpers
import rpmver

DATA = os.path.join(helpers.ROOT, "tests", "fixtures", "rpm-vercmp.at")
# The shared copy (header + upstream bytes). Changing it means changing meshTerm's copy in the same breath.
DATA_SHA256 = "af57ab23de41826d0a5ab22c7ad6e28242c4f84dbd6d03c8173a967842a07eb1"
UPSTREAM_SHA256 = "55df5ca66658a69b36d251f1ecef151a798baaac47d20a312ac8274718659438"
HEADER_LINES = 7
_CASE = re.compile(r"^RPMVERCMP\(([^,]*), ([^,]*), (-?[01])\)$")


def cases():
    """[(a, b, expected)] from every RPMVERCMP line not commented out with `dnl`."""
    with open(DATA, encoding="utf-8") as handle:
        lines = handle.read().split("\n")[HEADER_LINES:]
    out = []
    for line in lines:
        match = _CASE.match(line)
        if match:
            out.append((match.group(1), match.group(2), int(match.group(3))))
    return out


class SharedVectors(unittest.TestCase):
    def test_copy_is_pinned(self):
        with open(DATA, "rb") as handle:
            raw = handle.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), DATA_SHA256, "the shared copy drifted")
        lines = raw.split(b"\n")
        self.assertTrue(all(line.startswith(b"#") for line in lines[:HEADER_LINES]))
        upstream = b"\n".join(lines[HEADER_LINES:])
        self.assertEqual(hashlib.sha256(upstream).hexdigest(), UPSTREAM_SHA256)

    def test_rpm_vectors(self):
        got = cases()
        self.assertEqual(len(got), 91, "every non-dnl RPMVERCMP line of rpm-6.1.0's tests/rpmvercmp.at")
        for a, b, want in got:
            with self.subTest(a=a, b=b):
                self.assertEqual(rpmver.rpmvercmp(a, b), want)


class EVR(unittest.TestCase):
    def test_parse_and_validate(self):
        self.assertEqual(rpmver.parse("1:3.0.7-27.el9"), (1, "3.0.7", "27.el9"))
        self.assertEqual(rpmver.parse("0:8.1.14-1.module+el9.2.0+17911+b059dfc2"),
                         (0, "8.1.14", "1.module+el9.2.0+17911+b059dfc2"))
        self.assertEqual(rpmver.parse("3.0.7-27.el9"), (0, "3.0.7", "27.el9"))
        self.assertEqual(rpmver.parse("1.0"), (0, "1.0", None))
        for bad in ("", "1:", ":1.0-1", "1.0-1-2", "a:1.0-1", "1.0 -1", "1.0-", "-1", "1:2:3-4", None, "1.0-1\n"):
            with self.subTest(bad=bad):
                self.assertFalse(rpmver.validate(bad))

    def test_compare(self):
        self.assertEqual(rpmver.compare("1:1.0-1", "2.0-1"), 1, "the epoch first")
        self.assertEqual(rpmver.compare("0:1.0-1", "1.0-1"), 0, "a missing epoch is 0")
        self.assertEqual(rpmver.compare("3.0.7-27.el9", "1:3.0.7-27.el9"), -1)
        self.assertEqual(rpmver.compare("1:3.0.7-24.el9", "1:3.0.7-27.el9"), -1, "the release")
        self.assertEqual(rpmver.compare("1:3.0.7-27.el9_5", "1:3.0.7-27.el9"), 1)
        self.assertEqual(rpmver.compare("1.0", "1.0-5"), 0, "no release on one side: versions only")
        self.assertEqual(rpmver.compare("1.0~rc1-1", "1.0-1"), -1)
        self.assertEqual(rpmver.compare("1.0^git1-1", "1.0-1"), 1)
        # Alma's rebuild suffix is above RHEL's own build of the same release (Rocky data never fits Alma).
        self.assertEqual(rpmver.compare("1:3.0.7-27.el9.alma.1", "1:3.0.7-27.el9"), 1)
        sorted_list = sorted(["2.0-1", "1:0.1-1", "1.0-1", "1.0~rc1-1", "1.0-1.el9"], key=rpmver.sort_key)
        self.assertEqual(sorted_list, ["1.0~rc1-1", "1.0-1", "1.0-1.el9", "2.0-1", "1:0.1-1"])

    def test_modular(self):
        self.assertTrue(rpmver.is_modular("8.1.14-1.module_el9.2.0+24+ca6bd7c2"))
        self.assertTrue(rpmver.is_modular("0:8.1.14-1.module+el9.2.0+17911+b059dfc2"))
        self.assertFalse(rpmver.is_modular("1:3.0.7-27.el9"))
        self.assertEqual(rpmver.upstream_major_minor("8.1.14-1.module_el9.2.0+24+ca6bd7c2"), (8, 1))
        self.assertEqual(rpmver.upstream_major_minor("1:18.20.2-1.module_el9"), (18, 20))
        self.assertIsNone(rpmver.upstream_major_minor("20240101-1.el9"))


MODULE_MATCH = os.path.join(helpers.ROOT, "tests", "fixtures", "rpm-module-match.txt")


def module_cases():
    with open(MODULE_MATCH, encoding="utf-8") as handle:
        return [tuple(line.split("\t")) for line in handle.read().splitlines() if line and not line.startswith("#")]


class ModuleBuildTail(unittest.TestCase):
    """Review M1: modular builds compare without their module build ids (Rocky's rebuild ids are its own)."""

    def test_without_module_build(self):
        strip = rpmver.without_module_build
        self.assertEqual(strip("0:2.4.37-65.module+el8.10.0+40045+6ce8579b.6"), "0:2.4.37-65.module+el8.10.0.6")
        self.assertEqual(strip("2.4.37-65.module+el8.10.0+40402+af9563a3"), "2.4.37-65.module+el8.10.0")
        self.assertEqual(strip("8.1.32-1.module_el9.8.0+326+528679fc.alma.1"), "8.1.32-1.module_el9.8.0.alma.1")
        self.assertEqual(strip("1:3.5.8-2.el9_8"), "1:3.5.8-2.el9_8")
        self.assertEqual(strip("2.4.37"), "2.4.37", "no release")
        self.assertEqual(strip("not an evr-a-b"), "not an evr-a-b")
        self.assertEqual(strip("1-1.module+el8+1+abc"), "1-1.module+el8", "a major-only dist")

    def test_shared_vectors(self):
        got = module_cases()
        self.assertEqual(len(got), 15)
        for a, b, want in got:
            with self.subTest(a=a, b=b):
                self.assertEqual(rpmver.match_compare(a, b), int(want))
                self.assertEqual(rpmver.match_compare(b, a), -int(want))
        with open(MODULE_MATCH, "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), MODULE_MATCH_SHA256,
                             "the shared copy drifted (change meshTerm's in the same breath)")


MODULE_MATCH_SHA256 = "5b74d12ab656268b3c4ce028feedfce19ca5d3f8b355df30cddbcc2a40d76fb7"


if __name__ == "__main__":
    unittest.main()
