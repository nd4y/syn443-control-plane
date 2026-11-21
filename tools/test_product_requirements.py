import copy
import unittest

from product_requirements import compare, markdown


def item(id_, status):
    return {"id": id_, "text": "Secure transport " + id_, "status": status,
            "evidence": [] if status == "planned" else ["docs/example.md"]}


class ProductRequirementsTests(unittest.TestCase):
    def setUp(self):
        statuses = ["planned", "partial", "implemented", "verified"]
        self.android = {"specVersion": "0.9", "acceptanceCases": [],
                        "requirements": [item(f"T-{i}{j}", a) for i, a in enumerate(statuses)
                                         for j in range(len(statuses))]}
        self.control = copy.deepcopy(self.android)
        self.control["requirements"] = [item(f"T-{i}{j}", c) for i in range(len(statuses))
                                        for j, c in enumerate(statuses)]

    def test_every_component_combination_preserves_original_status(self):
        rows = compare(self.android, self.control)
        self.assertEqual([sum(row[-1] == zone for row in rows)
                          for zone in ("both", "android", "control", "neither")], [9, 3, 3, 1])
        self.assertIn(("requirements", "T-13", "partial", "verified", "both"), rows)
        report = markdown("0.9", "a" * 40, rows)
        self.assertIn("| Requirements | 16 | 9 | 3 | 3 | 1 |", report)
        self.assertIn("| Acceptance scenarios | 0 | 0 | 0 | 0 | 0 |", report)

    def test_order_is_not_identity(self):
        rows = compare(self.android, self.control)
        self.android["requirements"].reverse()
        self.assertEqual(rows, compare(self.android, self.control))

    def test_drift_or_unsubstantiated_component_status_fails(self):
        changes = [
            lambda d: d.update(specVersion="0.10"),
            lambda d: d["requirements"].pop(),
            lambda d: d["requirements"].append(d["requirements"][0]),
            lambda d: d["requirements"][0].update(text="Different scope"),
            lambda d: d["requirements"][0].update(status="verified"),
            lambda d: d["requirements"][0].update(status="complete"),
        ]
        for change in changes:
            with self.subTest(change=change):
                doc = copy.deepcopy(self.control)
                change(doc)
                with self.assertRaises(ValueError):
                    compare(self.android, doc)

    def test_acceptance_scenario_is_compared_separately(self):
        scenario = {"id": "AC01", "specRow": " one | two |", "status": "planned", "evidence": []}
        for doc in (self.android, self.control):
            doc["acceptanceCases"].append(dict(scenario))
        self.assertIn(("acceptanceCases", "AC01", "planned", "planned", "neither"), compare(self.android, self.control))
        self.android["acceptanceCases"][0]["specRow"] = " changed | two |"
        with self.assertRaisesRegex(ValueError, "AC01"):
            compare(self.android, self.control)
