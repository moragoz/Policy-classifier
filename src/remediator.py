from copy import deepcopy


def remediate_policy(policy: dict, findings: list[dict]) -> dict:
    remediated = deepcopy(policy)
    changes = []

    statements = remediated.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
        remediated["Statement"] = statements

    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        if statement.get("Action") == "*":
            statement["Action"] = [
                "s3:GetObject",
                "s3:ListBucket"
            ]
            changes.append({
                "statement_index": index,
                "change": "Replaced wildcard Action '*' with limited read-only S3 actions.",
                "reason": "Wildcard actions allow unrestricted access. The remediation applies least privilege."
            })

        if statement.get("Resource") == "*":
            statement["Resource"] = [
                "arn:aws:s3:::example-bucket",
                "arn:aws:s3:::example-bucket/*"
            ]
            changes.append({
                "statement_index": index,
                "change": "Replaced wildcard Resource '*' with a specific S3 bucket ARN.",
                "reason": "Wildcard resources allow access to all resources. The remediation scopes access to one bucket."
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
        "remediated_policy": remediated,
        "changes": changes
    }