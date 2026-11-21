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
