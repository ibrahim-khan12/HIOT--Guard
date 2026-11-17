"""Offline device-category inference from passive discovery recordings."""

MEDICAL = ("infusion_pump", "ct", "mri", "ultrasound", "portable_xray",
           "bedside_monitor", "lab_analyzer", "ventilator", "dialysis_machine", "ecg_monitor")
ROLE_LABELS = dict(zip(("pump", "modality", "mri", "ultrasound", "xray", "monitor",
                        "lab_analyzer", "ventilator", "dialysis", "ecg"), MEDICAL))
OTHER = "other"
UNKNOWN = "unknown"
