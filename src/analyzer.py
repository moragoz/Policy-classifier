CRITICAL_ACTIONS = {
    "*",
    "iam:*",
    "administratoraccess"
}

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole"
}


def normalize_to_list(value):
    if isinstance(value, list):
        return value
    return [value]


def analyze_policy(policy: dict) -> list[dict]:
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements):
        effect = statement.get("Effect")
        actions = normalize_to_list(statement.get("Action", []))
        resources = normalize_to_list(statement.get("Resource", []))
        not_actions = normalize_to_list(statement.get("NotAction", []))

        if effect != "Allow":
            continue

        # ---- ACTIONS ----
        for action in actions:
            if action == "*":
                findings.append({
                    "severity": "critical",
                    "score": 5,
                    "issue": "Wildcard action",
                    "evidence": f"Statement {index} uses Action: *"
                })

            if action.endswith(":*"):
                findings.append({
                    "severity": "high",
                    "score": 3,
                    "issue": "Service-level wildcard action",
                    "evidence": f"Statement {index} uses {action}"
                })

            if action in PRIVILEGE_ESCALATION_ACTIONS:
                findings.append({
                    "severity": "critical",
                    "score": 5,
                    "issue": "Privilege escalation action",
                    "evidence": f"Statement {index} uses {action}"
                })

            # 🔥 חדש — פעולות הרסניות
            if "Delete" in action or "Terminate" in action:
                findings.append({
                    "severity": "high",
                    "score": 3,
                    "issue": "Destructive action",
                    "evidence": f"Statement {index} uses destructive action {action}"
                })

        # ---- RESOURCES ----
        for resource in resources:
            if resource == "*":
                findings.append({
                    "severity": "critical",
                    "score": 5,
                    "issue": "Wildcard resource",
                    "evidence": f"Statement {index} uses Resource: *"
                })

            # 🔥 חדש — wildcard בתוך ARN
            if isinstance(resource, str) and "*" in resource:
                findings.append({
                    "severity": "medium",
                    "score": 2,
                    "issue": "Wildcard in resource ARN",
                    "evidence": f"Statement {index} uses wildcard in resource {resource}"
                })

        # ---- NOT ACTIONS ----
        for not_action in not_actions:
            if not_action:
                findings.append({
                    "severity": "high",
                    "score": 4,
                    "issue": "Allow with NotAction",
                    "evidence": f"Statement {index} uses NotAction with Allow effect"
                })

        # ---- CONDITIONS ----
        if "Condition" not in statement:
            findings.append({
                "severity": "medium",
                "score": 2,
                "issue": "Missing condition",
                "evidence": f"Statement {index} has no Condition"
            })

    return findings