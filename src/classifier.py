from src.analyzer import analyze_policy
from src.remediator import remediate_policy
from src.validator import validate_policy
from src.llm_agent import llm_security_review

WEAK_THRESHOLD = 4


def classify_policy(policy: dict) -> dict:
    original_validation = validate_policy(policy)

    if not original_validation["valid"]:
        return {
            "classification": "Weak",
            "risk_score": 999,
            "findings": [
                {
                    "severity": "critical",
                    "score": 999,
                    "issue": "Invalid IAM policy structure",
                    "evidence": "; ".join(original_validation["errors"])
                }
            ],
            "reason": "The policy is weak because it is not a valid IAM policy structure.",
            "llm_review": {
                "used_llm": False,
                "summary": "LLM review skipped because the policy structure is invalid."
            }
        }

    findings = analyze_policy(policy)
    risk_score = sum(f["score"] for f in findings)

    classification = "Weak" if risk_score >= WEAK_THRESHOLD else "Strong"

    result = {
        "classification": classification,
        "risk_score": risk_score,
        "findings": findings,
        "reason": build_reason(classification, findings),
        "llm_review": llm_security_review(policy, findings, classification)
    }

    if classification == "Weak":
        remediation = remediate_policy(policy, findings)
        remediation["validation"] = validate_policy(remediation["remediated_policy"])
        result["remediation"] = remediation

    return result


def build_reason(classification: str, findings: list[dict]) -> str:
    if classification == "Strong":
        return "The policy follows least-privilege principles and contains no high-risk findings."

    issues = [f["issue"] for f in findings]
    return "The policy is weak because it contains: " + ", ".join(sorted(set(issues)))