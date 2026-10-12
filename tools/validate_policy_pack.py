#!/usr/bin/env python3
"""校验地方政策包字段完整性。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "data" / "jurisdiction_policy_pack_v1.json"
REQUIRED = ["policy_id", "name", "value", "unit", "effective_from", "source_name", "source_url", "status", "verified_at", "verified_by"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default=str(DEFAULT))
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
    errors = []
    warnings = []
    for profile in payload.get("profiles", []):
        for policy in profile.get("policies", []):
            missing = [field for field in REQUIRED if field not in policy]
            if missing:
                errors.append(f"{profile['jurisdiction']} / {policy.get('policy_id')} 缺字段：{', '.join(missing)}")
            if policy.get("status") != "verified":
                warnings.append(f"{profile['jurisdiction']} / {policy.get('policy_id')} 尚未核验")
            if policy.get("status") == "verified":
                if policy.get("value") in (None, "") and policy.get("unit") != "policy_rule":
                    errors.append(f"{profile['jurisdiction']} / {policy['policy_id']} 已标记 verified 但缺少数值")
                if not policy.get("effective_from") or not policy.get("verified_at") or not policy.get("verified_by"):
                    errors.append(f"{profile['jurisdiction']} / {policy['policy_id']} 已标记 verified 但缺少日期或核验人")

    print(f"profiles={len(payload.get('profiles', []))}")
    print(f"errors={len(errors)} warnings={len(warnings)}")
    for item in errors:
        print(f"ERROR: {item}")
    for item in warnings:
        print(f"WARN: {item}")

    if errors or (args.strict and warnings):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
