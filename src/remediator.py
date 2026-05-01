from copy import deepcopy

from src.llm_agent import infer_policy_intent


FALLBACK_ACTIONS = ["s3:GetObject", "s3:ListBucket"]
FALLBACK_RESOURCES = [
    "arn:aws:s3:::example-bucket",
    "arn:aws:s3:::example-bucket/*"
]


def remediate_policy(policy: dict, findings: list[dict]) -> dict:
    remediated = deepcopy(policy)
    changes = []

    intent = infer_policy_intent(policy, findings)

    suggested_actions = intent.get("actions") or FALLBACK_ACTIONS
    suggested_resource = intent.get("resource_hint")

    if suggested_resource:
        suggested_resources = [suggested_resource]
    else:
        suggested_resources = FALLBACK_RESOURCES

    statements = remediated.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
        remediated["Statement"] = statements

    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        if statement.get("Action") == "*":
            statement["Action"] = suggested_actions
            changes.append({
                "statement_index": index,
                "change": "Replaced wildcard Action '*' with inferred least-privilege actions.",
                "reason": f"Intent inference result: {intent.get('reason')}"
            })

        if statement.get("Resource") == "*":
            statement["Resource"] = suggested_resources
            changes.append({
                "statement_index": index,
                "change": "Replaced wildcard Resource '*' with scoped resource hint.",
                "reason": "Wildcard resources allow access to all resources. The remediation scopes access based on inferred intent or fallback policy."
            })

        if "NotAction" in statement:
            statement.pop("NotAction", None)
            if "Action" not in statement:
                statement["Action"] = suggested_actions

            changes.append({
                "statement_index": index,
                "change": "Removed NotAction and replaced it with explicit allowed actions.",
                "reason": "Allow with NotAction can unintentionally grant broad access. Explicit Action is safer."
            })

        if "Condition" not in statement:
            statement["Condition"] = {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
            changes.append({
                "statement_index": index,
                "change": "Added MFA condition.",
                "reason": "Requiring MFA reduces the risk of unauthorized access."
            })

    return {
        "intent_inference": intent,
        "remediated_policy": remediated,
        "changes": changes
    }