import json
import os
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).parent.parent / '.env')


def llm_security_review(policy: dict, findings: list[dict], classification: str) -> dict:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return {
            "used_llm": False,
            "summary": "LLM review was skipped because OPENAI_API_KEY is not configured.",
            "security_reasoning": None
        }

    client = OpenAI(api_key=api_key)

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
            model="gpt-4o-mini",
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

        try:
            parsed = json.loads(content)
            parsed["used_llm"] = True
            return parsed
        except json.JSONDecodeError:
            return {
                "used_llm": True,
                "summary": "LLM returned non-JSON output.",
                "raw_output": content
            }
    except Exception as e:
        return {
            "used_llm": False,
            "summary": f"LLM review failed due to API error: {str(e)}",
            "security_reasoning": None
        }