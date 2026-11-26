"""Project the saved Module 4 scorecard into a small dashboard summary."""

import json


MAX_REPORT_BYTES = 8 * 1024 * 1024
MODELS = {"rf": "Random Forest", "hgb": "Histogram gradient boosting"}
FEATURES = {"semantics": "Semantic features", "traffic": "Traffic features",
            "combined": "Semantic and traffic features"}


def count(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("Unexpected evaluation count")
    return value


def f1(value):
    if type(value) not in (int, float) or not 0 <= value <= 1:
        raise ValueError("Unexpected macro F1")
    return value


def load_evaluation(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Module 4 evaluation report exceeds the dashboard size limit")
    report = json.loads(raw)
    if not isinstance(report, dict) or report.get("version") != "module4-final-v1":
        raise ValueError("Expected a Module 4 final study report")
    try:
        window = count(report["primary_window_seconds"], minimum=1)
        algorithm, family = report["selected"]["candidate"].split("_", 1)
        cohorts = []
        for key, name in (("familiar", "Familiar Python"), ("transfer", "HAPI/DCMTK transfer")):
            cohort = report["cohorts"][key]
            scored = cohort["windows"][str(window)]
            increment = scored["rule_abstention_increment"]
            cohorts.append({
                "name": name,
                "sessions": count(cohort["sessions"], minimum=1),
                "rules_f1": f1(scored["methods"]["updated_rules"]["macro_f1"]),
                "fallback_f1": f1(scored["methods"]["selected_fallback"]["macro_f1"]),
                "additional_correct": count(increment["additional_correct"]),
                "additional_wrong": count(increment["additional_wrong"]),
            })
        return {"window_seconds": window, "model": MODELS[algorithm],
                "features": FEATURES[family], "cohorts": cohorts}
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ValueError("Invalid Module 4 evaluation summary fields") from error
