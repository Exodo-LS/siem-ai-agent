# agent/validator.py
# Validates Claude's triage JSON output against expected schema

REQUIRED_TOP_KEYS = {"incidents", "summary", "escalate"}
REQUIRED_INCIDENT_KEYS = {"id", "threat", "severity", "mitre_tactic",
                           "mitre_technique", "recommended_action",
                           "false_positive_likelihood"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_FP = {"low", "medium", "high"}

def validate_triage_json(parsed: dict) -> tuple[bool, list[str]]:
    """
    Validates parsed Claude JSON output.
    Returns (is_valid, list_of_errors).
    """
    errors = []

    # Top-level keys
    missing_top = REQUIRED_TOP_KEYS - parsed.keys()
    if missing_top:
        errors.append(f"Missing top-level keys: {missing_top}")

    # Type checks
    if not isinstance(parsed.get("incidents"), list):
        errors.append("'incidents' must be a list")
        return False, errors

    if not isinstance(parsed.get("summary"), str):
        errors.append("'summary' must be a string")

    if not isinstance(parsed.get("escalate"), bool):
        errors.append("'escalate' must be a boolean")

    # Per-incident validation
    for i, inc in enumerate(parsed.get("incidents", [])):
        missing = REQUIRED_INCIDENT_KEYS - inc.keys()
        if missing:
            errors.append(f"Incident {i} missing keys: {missing}")

        if inc.get("severity") not in VALID_SEVERITIES:
            errors.append(f"Incident {i} invalid severity: {inc.get('severity')}")

        if inc.get("false_positive_likelihood") not in VALID_FP:
            errors.append(f"Incident {i} invalid FP likelihood: {inc.get('false_positive_likelihood')}")

    return len(errors) == 0, errors
