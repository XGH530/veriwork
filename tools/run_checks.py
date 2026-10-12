#!/usr/bin/env python3
"""运行职安盾提交前检查。"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def find_node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    candidates = [
        Path(os.environ.get("ProgramFiles", "")) / "Microsoft Visual Studio/2022/Community/MSBuild/Microsoft/VisualStudio/NodeJs/node.exe",
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio/2022/BuildTools/MSBuild/Microsoft/VisualStudio/NodeJs/node.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def run(label: str, command: list[str]) -> None:
    print(f"\n[{label}] {' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    python = sys.executable
    run("server syntax", [python, "-m", "py_compile", "server.py"])
    run("backend tests", [python, "-m", "unittest", "discover", "-s", "tests", "-v"])
    run("development regression", [python, "tools/evaluate_rules.py"])
    run("frozen holdout report", [python, "tools/evaluate_rules.py", "--dataset", "data/holdout_cases_v2_frozen.json", "--output-prefix", "frozen_holdout_v2_report"])
    run("policy pack validation", [python, "tools/validate_policy_pack.py"])
    run("comparison dashboard", [python, "tools/build_comparison.py"])

    node = find_node()
    if node:
        run("frontend smoke", [node, "tests/frontend_smoke.js"])
    else:
        print("\n[frontend smoke] SKIP: Node.js not found")

    print("\nAll available checks completed.")


if __name__ == "__main__":
    main()
