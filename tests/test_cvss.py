import json
import os
import unittest

import helpers  # noqa: F401  (sys.path)
import cvss

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class FirstExamples(unittest.TestCase):
    """Every score table on FIRST's CVSS v4.0 examples page (it gives the v3.1 score next to each v4.0 one,
    and v4.0 BTE scores for the vectors with threat/environmental metrics)."""

    def test_first_tables(self):
        with open(os.path.join(FIXTURES, "first-cvss-examples.json")) as handle:
            cases = json.load(handle)["cases"]
        self.assertGreaterEqual(len(cases), 50)
        kinds = {v.split("/")[0] for v, _ in cases}
        self.assertEqual(kinds, {"CVSS:3.1", "CVSS:4.0"})
        for vector, want in cases:
            with self.subTest(vector=vector):
                self.assertAlmostEqual(cvss.base_score(vector), want, places=9)


class V3(unittest.TestCase):
    def test_v31_spec_examples(self):
        # FIRST CVSS v3.1 examples document.
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,     # CVE-2014-0160 Heartbleed
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,     # CVE-2014-6271 Shellshock
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,     # CVE-2014-3566 POODLE
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,     # CVE-2013-1937 phpMyAdmin XSS
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,     # CVE-2012-1516 VMware guest escape
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 7.8,     # CVE-2015-1098 iWork
        }
        for vector, want in cases.items():
            self.assertEqual(cvss.base_score(vector), want, vector)

    def test_roundup_avoids_float_drift(self):
        # v3.1 Appendix A: Roundup(4.02) is 4.1 and Roundup(4.00) is 4.0; a value a float error above a
        # tenth (4.000000000000001) must not round up.
        self.assertEqual(cvss._roundup_31(4.02), 4.1)
        self.assertEqual(cvss._roundup_31(4.00), 4.0)
        self.assertEqual(cvss._roundup_31(4.000000000000001), 4.0)
        self.assertEqual(cvss._roundup_30(4.02), 4.1)

    def test_v30_vectors_score(self):
        self.assertEqual(cvss.base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

    def test_no_impact_is_zero(self):
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertEqual(cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"), 0.0)


class V4(unittest.TestCase):
    def test_debian_style_all_x_vector(self):
        # Debian writes every optional metric as X; apt CVE-2026-109518's vector is High.
        vector = ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X"
                  "/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X")
        score = cvss.base_score(vector)
        self.assertEqual(score, cvss.base_score(vector.split("/E:")[0]))
        self.assertEqual(cvss.band(score), cvss.HIGH)

    def test_refuses_bad_vectors(self):
        for bad in ("CVSS:4.0/AV:N/AC:L", "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:2.0/AV:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None):
            with self.subTest(bad=bad):
                with self.assertRaises(cvss.CVSSError):
                    cvss.base_score(bad)


class Bands(unittest.TestCase):
    def test_bands(self):
        self.assertEqual([cvss.band(s) for s in (10.0, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0)],
                         [4, 4, 3, 3, 2, 2, 1, 1, 0])


if __name__ == "__main__":
    unittest.main()
