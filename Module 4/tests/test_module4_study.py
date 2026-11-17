import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

from module4 import UNKNOWN
from module4.experiment import train, write_json
from module4.study import (HEART_PAIR, selected_predictions, specifications, study_profile)
from test_module4 import fixture


class DatasetStudyTests(unittest.TestCase):
    def test_new_splits_have_disjoint_sessions_and_complete_profiles(self):
        used = set()
        for split, count in (("training", 30), ("validation", 10), ("test", 12)):
            specs = specifications(split)
            self.assertEqual(len(specs), count)
            ids = {spec["session"] for spec in specs}
            self.assertFalse(used & ids)
            used.update(ids)
            for spec in specs:
                settings, properties, startup, schedule = study_profile(spec)
                self.assertEqual(len(settings["addresses"]), 15)
                self.assertEqual(len(set(settings["addresses"].values())), 15)
                self.assertEqual(set(properties), set(startup))
                self.assertTrue({"pump", "modality", "ecg", "monitor"} <=
                                {task[1] for task in schedule})
                self.assertTrue(all(0 < number < 255 for number in settings["addresses"].values()))

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "Install requirements-module4.txt")
    def test_shared_heart_rate_abstention_preserves_other_rules_and_input(self):
        from joblib import load

        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            for index, split in enumerate(("training", "validation")):
                record, labels = fixture(split, index)
                write_json(folder / f"{split}-data.json", record)
                write_json(folder / f"{split}.json", {"recordings": [
                    {"recording": f"{split}-data.json", "endpoints": labels}]})
            train(folder / "training.json", folder / "validation.json", folder / "fit")
            model = load(folder / "fit/model.joblib")
            record, _ = fixture("fresh", 8)
            previous = copy.deepcopy(record)
            outcomes = selected_predictions(record, model, {"threshold": 0.0})
            heart = [row for row in outcomes if row["ip"].endswith((".6", ".10"))]
            self.assertEqual(len(heart), len(HEART_PAIR))
            for row in heart:
                self.assertEqual(row["decisions"]["selected_forest"]["category"], UNKNOWN)
                self.assertEqual(row["decisions"]["selected_forest"]["reason"], "shared_heart_rate_evidence")
            pump = outcomes[0]
            self.assertEqual(pump["decisions"]["selected_fallback"]["category"], "infusion_pump")
            self.assertEqual(record, previous)


if __name__ == "__main__":
    unittest.main()
