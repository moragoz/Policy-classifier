import json
import time
from pathlib import Path

from src.classifier import classify_policy


def load_evaluation_set(path: str) -> list[dict]:
    with Path(path).open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def main():
    dataset_path = "evaluation/evaluation_set.json"
    evaluation_set = load_evaluation_set(dataset_path)

    results = []
    correct = 0
    start_total = time.perf_counter()

    for item in evaluation_set:
        start = time.perf_counter()

        result = classify_policy(item["policy"])

        elapsed = time.perf_counter() - start

        predicted = result["classification"]
        expected = item["expected_classification"]

        is_correct = predicted == expected

        if is_correct:
            correct += 1

        remediation = result.get("remediation")

        results.append({
            "name": item["name"],
            "expected": expected,
            "predicted": predicted,
            "correct": is_correct,
            "risk_score": result["risk_score"],
            "time_seconds": round(elapsed, 6),
            "findings_count": len(result["findings"]),

            # LLM usage
            "llm_used": result.get("llm_review", {}).get("used_llm", False),

            # Remediation information
            "remediation_generated": remediation is not None,

            "remediation_valid": (
                remediation.get("validation", {}).get("valid")
                if remediation
                else None
            ),

            "intent_inference": (
                remediation.get("intent_inference")
                if remediation
                else None
            ),

            "remediated_policy": (
                remediation.get("remediated_policy")
                if remediation
                else None
            ),

            "remediation_changes": (
                remediation.get("changes")
                if remediation
                else None
            )
        })

    total_time = time.perf_counter() - start_total
    total = len(evaluation_set)

    agreement_rate = correct / total if total else 0

    report = {
        "total_policies": total,
        "correct": correct,
        "agreement_rate": round(agreement_rate, 4),
        "agreement_rate_percent": round(agreement_rate * 100, 2),
        "total_time_seconds": round(total_time, 6),
        "average_time_seconds": round(total_time / total, 6) if total else 0,
        "results": results
    }

    output_path = Path("evaluation/evaluation_report.json")

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"Evaluation report saved to {output_path}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()