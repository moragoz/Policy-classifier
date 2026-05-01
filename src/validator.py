def validate_policy(policy: dict) -> dict:
    errors = []

    if not isinstance(policy, dict):
        errors.append("Policy must be a JSON object.")
        return {"valid": False, "errors": errors}

    if "Version" not in policy:
        errors.append("Missing required field: Version.")

    if "Statement" not in policy:
        errors.append("Missing required field: Statement.")
        return {"valid": False, "errors": errors}

    statements = policy["Statement"]

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        errors.append("Statement must be an object or a list.")

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            errors.append(f"Statement {index} must be an object.")
            continue

        if "Effect" not in statement:
            errors.append(f"Statement {index} is missing Effect.")

        if statement.get("Effect") not in ["Allow", "Deny"]:
            errors.append(f"Statement {index} has invalid Effect.")

        has_action = "Action" in statement or "NotAction" in statement
        if not has_action:
            errors.append(f"Statement {index} is missing Action or NotAction.")

        has_resource = "Resource" in statement or "NotResource" in statement
        if not has_resource:
            errors.append(f"Statement {index} is missing Resource or NotResource.")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }