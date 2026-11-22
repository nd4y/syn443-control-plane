import json
import unittest

from check_web_image_acceptance import PACKAGE, REQUIRED, report


def event(action, name=None, package=PACKAGE):
    data = {"Action": action, "Package": package}
    if name is not None:
        data["Test"] = name
    return json.dumps(data)


class WebImageAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.lines = [event("start"), *(event(action, name) for name in REQUIRED for action in ("run", "pass")), event("pass")]

    def test_requires_real_packaged_cases_for_both_modes(self):
        self.assertEqual(report(self.lines)["passed"], REQUIRED)
        for change in (lambda lines: lines[:-1], lambda lines: lines[:3] + lines[5:],
                       lambda lines: lines + [event("pass", REQUIRED[0])],
                       lambda lines: [v.replace(PACKAGE, "foreign") for v in lines],
                       lambda lines: lines + [event("skip", REQUIRED[1])]):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(change(self.lines))


    def test_failure_reports_a_public_source_location_without_fixture_values(self):
        name = REQUIRED[-1]
        failure = json.dumps({"Package": PACKAGE, "Test": name, "Action": "output",
                              "Output": "    personal_issuance_test.go:34: HTTP status 403, expected 200 (synthetic-private-body)"})
        with self.assertRaises(ValueError) as caught:
            report([event("start"), event("run", name), failure, event("fail", name)])
        self.assertIn("personal_issuance_test.go:34 (HTTP 403, expected 200)", str(caught.exception))
        self.assertNotIn("synthetic-private-body", str(caught.exception))
