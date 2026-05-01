import json
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


MODEL_NAME = "gpt-4o-mini"


def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return None

    return OpenAI(api_key=api_key)


def llm_security_review(policy: dict, findings: list[dict], classification: str) -> dict:
    client = get_openai_client()

    if client is None:
        return {
            "used_llm": False,
            "summary": "LLM review was skipped because OPENAI_API_KEY is not configured.",
            "security_reasoning": None,
            "confidence": "low"
        }

    prompt = f"""
You are a senior cloud security engineer reviewing an AWS IAM policy.

Given:
1. The IAM policy JSON
2. Rule-based security findings
3. Initial classification

Your task:
- Validate whether the classification makes sense
- Explain the security risk clearly
- Mention the principle of least privilege when relevant
- Do not invent missing business context
- Return only valid JSON

IAM Policy:
{json.dumps(policy, indent=2)}

Findings:
{json.dumps(findings, indent=2)}

Initial classification:
{classification}

Return JSON in this format:
{{
  "llm_classification": "Weak or Strong",
  "security_reasoning": "clear explanation",
  "confidence": "low, medium, or high"
}}
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert AWS IAM security reviewer."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0
        )

        content = response.choices[0].message.content
        parsed = json.loads(content)
        parsed["used_llm"] = True
        return parsed

    except Exception as error:
        return {
            "used_llm": False,
            "summary": f"LLM review failed due to API error: {str(error)}",
            "security_reasoning": None,
            "confidence": "low"
        }


def infer_policy_intent(policy: dict, findings: list[dict]) -> dict:
    client = get_openai_client()

    if client is None:
        return {
            "used_llm": False,
            "intent": "unknown",
            "service": "unknown",
            "actions": [],
            "resource_hint": None,
            "confidence": "low",
            "reason": "LLM intent inference skipped because OPENAI_API_KEY is not configured."
        }

    prompt = f"""
You are a senior AWS cloud security engineer.

Given an overly permissive IAM policy and rule-based security findings,
infer the most likely original intent of the policy.

Important rules:
- Do not invent business context.
- If the intent cannot be inferred, return "unknown".
- Prefer conservative least-privilege suggestions.
- Suggested actions must be valid AWS IAM action strings.
- Suggested resource_hint must be a scoped AWS ARN string or null.
- Return only valid JSON.

IAM Policy:
{json.dumps(policy, indent=2)}

Findings:
{json.dumps(findings, indent=2)}

Return JSON in this format:
{{
  "intent": "short description of likely intent",
  "service": "s3 | ec2 | dynamodb | lambda | cloudwatch | iam | kms | unknown",
  "actions": ["least privilege action list"],
  "resource_hint": "suggested scoped AWS ARN or null",
  "confidence": "low | medium | high",
  "reason": "explain how the intent was inferred"
}}
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "You infer least-privilege intent from AWS IAM policies."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0
        )

        content = response.choices[0].message.content
        parsed = json.loads(content)

        return {
            "used_llm": True,
            "intent": parsed.get("intent", "unknown"),
            "service": parsed.get("service", "unknown"),
            "actions": parsed.get("actions", []),
            "resource_hint": parsed.get("resource_hint"),
            "confidence": parsed.get("confidence", "low"),
            "reason": parsed.get("reason", "No reason provided.")
        }

    except Exception as error:
        return {
            "used_llm": False,
            "intent": "unknown",
            "service": "unknown",
            "actions": [],
            "resource_hint": None,
            "confidence": "low",
            "reason": f"LLM intent inference failed due to API error: {str(error)}"
        }