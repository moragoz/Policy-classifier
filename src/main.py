import json
import sys
from pathlib import Path

from src.classifier import classify_policy


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m src.main <policy.json>")
        return

    policy_path = Path(sys.argv[1])

    with policy_path.open("r", encoding="utf-8-sig") as file:
        content = file.read()

    policy = json.loads(content)

    result = classify_policy(policy)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()