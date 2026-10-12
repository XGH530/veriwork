#!/usr/bin/env python3
"""公平对照：同一次模型输出同时计算模型直答与职安盾混合链。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from tools.evaluate_llm import call_model  # noqa: E402
from tools.evaluate_rules import metric_block  # noqa: E402

RESULTS = ROOT / "results"
RISK_IDS = {risk["id"] for risk in server.RISKS}


def make_row(case: dict, system: str, predicted: set[str], abstain: bool, citation_count: int, elapsed_ms: int) -> dict:
    expected = set(case["expected_risks"])
    return {
        "id": case["id"],
        "split": case["split"],
        "family": case["family"],
        "difficulty": case["difficulty"],
        "title": case["title"],
        "text": case["text"],
        "system": system,
        "expected_risks": sorted(expected),
        "predicted_risks": sorted(predicted),
        "true_positive": sorted(expected & predicted),
        "false_positive": sorted(predicted - expected),
        "false_negative": sorted(expected - predicted),
        "expected_abstain": bool(case["expected_abstain"]),
        "predicted_abstain": abstain,
        "predicted_risk_count": len(predicted),
        "risks_with_citation": citation_count,
        "processing_ms": elapsed_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(ROOT / "data" / "holdout_cases_v2_frozen.json"))
    parser.add_argument("--api-url", default=os.environ.get("LLM_API_URL", ""))
    parser.add_argument("--api-key-env", default="LLM_API_KEY")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", "model-name"))
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output-prefix", default="llm_pair_comparison")
    parser.add_argument("--resume", action="store_true", help="复用已有成功结果，只补失败样本")
    args = parser.parse_args()

    api_key = os.environ.get(args.api_key_env, "")
    if not args.api_url or not api_key:
        raise SystemExit(f"缺少 --api-url 或环境变量 {args.api_key_env}")

    payload = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    model_rows = []
    hybrid_rows = []
    errors = []
    existing_model = {}
    existing_hybrid = {}

    result_path = RESULTS / f"{args.output_prefix}.json"
    if args.resume and result_path.exists():
        previous = json.loads(result_path.read_text(encoding="utf-8"))
        for row in previous.get("systems", {}).get("model_only", {}).get("cases", []):
            if not row.get("error"):
                existing_model[row["id"]] = row
        for row in previous.get("systems", {}).get("veriwork_hybrid", {}).get("cases", []):
            if not row.get("error"):
                existing_hybrid[row["id"]] = row
        print(f"Resume: loaded {len(existing_model)} successful cases")

    for index, case in enumerate(payload["cases"], start=1):
        if case["id"] in existing_model and case["id"] in existing_hybrid:
            model_rows.append(existing_model[case["id"]])
            hybrid_rows.append(existing_hybrid[case["id"]])
            print(f"[{index}/{len(payload['cases'])}] {case['id']} reused")
            continue
        print(f"[{index}/{len(payload['cases'])}] {case['id']}")
        started = time.perf_counter()
        try:
            model_result = call_model(args.api_url, api_key, args.model, case["text"], args.temperature, args.timeout)
        except (urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"id": case["id"], "error": f"{type(exc).__name__}: {exc}"})
            continue

        elapsed_ms = max(1, round((time.perf_counter() - started) * 1000))
        model_risks = {risk_id for risk_id in model_result.get("risks", []) if risk_id in RISK_IDS}
        rule_result = server.deterministic_analysis(case["text"], "劳动合同", "全国规则")
        rule_risks = {risk["id"] for risk in rule_result["risks"]}
        hybrid_risks = model_risks | rule_risks
        model_abstain = bool(model_result.get("abstain", False))
        hybrid_abstain = model_abstain or bool(rule_result["requiresHumanReview"])

        model_rows.append(make_row(case, "LLM model-only", model_risks, model_abstain, 0, elapsed_ms))
        hybrid_rows.append(make_row(case, "VeriWork hybrid", hybrid_risks, hybrid_abstain, len(hybrid_risks), elapsed_ms))

    if not model_rows:
        raise SystemExit(f"所有请求失败。首个错误：{errors[0] if errors else 'unknown'}")

    def report_for(system: str, rows: list[dict]) -> dict:
        split_names = sorted({row["split"] for row in rows})
        return {
            "system": system,
            "model": args.model,
            "dataset_version": payload["version"],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "successful_cases": len(rows),
            "failed_cases": len(errors),
            "errors": errors,
            "metrics": {
                **{name: metric_block([row for row in rows if row["split"] == name]) for name in split_names},
                "all": metric_block(rows),
            },
            "cases": rows,
        }

    report = {
        "model": args.model,
        "dataset_version": payload["version"],
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "comparison_protocol": "同一次模型输出同时计算 model-only 和规则并集，避免重复采样的不可比问题。",
        "successful_cases": len(model_rows),
        "failed_cases": len(errors),
        "errors": errors,
        "systems": {
            "model_only": report_for("LLM model-only", model_rows),
            "veriwork_hybrid": report_for("VeriWork hybrid", hybrid_rows),
        },
    }

    json_path = RESULTS / f"{args.output_prefix}.json"
    md_path = RESULTS / f"{args.output_prefix}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    model_metrics = report["systems"]["model_only"]["metrics"]["all"]
    hybrid_metrics = report["systems"]["veriwork_hybrid"]["metrics"]["all"]
    lines = [
        "# 同模型公平对照实验",
        "",
        f"- 模型：{args.model}",
        f"- 数据集：{payload['version']}",
        f"- 成功样本：{len(model_rows)}",
        f"- 失败请求：{len(errors)}",
        "",
        "| 系统 | Precision | Recall | F1 | 法源覆盖 | 待核实召回 |",
        "|---|---:|---:|---:|---:|---:|",
        f"| 通用模型直答 | {model_metrics['precision']:.1%} | {model_metrics['recall']:.1%} | {model_metrics['f1']:.1%} | {model_metrics['citation_coverage']:.1%} | {model_metrics['abstention_recall']:.1%} |",
        f"| 职安盾混合链 | {hybrid_metrics['precision']:.1%} | {hybrid_metrics['recall']:.1%} | {hybrid_metrics['f1']:.1%} | {hybrid_metrics['citation_coverage']:.1%} | {hybrid_metrics['abstention_recall']:.1%} |",
        "",
        "两组结果使用同一次模型输出，规则链只增加候选风险，不修改模型已经给出的风险ID。",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json_path)
    print(md_path)


if __name__ == "__main__":
    main()
