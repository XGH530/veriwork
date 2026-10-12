#!/usr/bin/env python3
"""运行职安盾确定性规则链的可复现评测。"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import server  # noqa: E402

DEFAULT_DATASET = ROOT / "data" / "evaluation_cases_v1.json"
RESULTS = ROOT / "results"
RESULTS.mkdir(parents=True, exist_ok=True)


def divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def metric_block(rows: list[dict]) -> dict:
    expected_total = sum(len(row["expected_risks"]) for row in rows)
    predicted_total = sum(len(row["predicted_risks"]) for row in rows)
    true_positive = sum(len(row["true_positive"]) for row in rows)
    false_positive = sum(len(row["false_positive"]) for row in rows)
    false_negative = sum(len(row["false_negative"]) for row in rows)
    precision = divide(true_positive, true_positive + false_positive)
    recall = divide(true_positive, true_positive + false_negative)
    f1 = divide(2 * precision * recall, precision + recall) if precision + recall else 0.0
    exact_match = sum(1 for row in rows if not row["false_positive"] and not row["false_negative"])
    abstention_rows = [row for row in rows if row["expected_abstain"]]
    abstention_correct = sum(1 for row in abstention_rows if row["predicted_abstain"])
    confident_error_rows = [
        row for row in rows
        if row["expected_abstain"] and not row["predicted_abstain"]
    ]
    citation_denominator = sum(row["predicted_risk_count"] for row in rows)
    citation_numerator = sum(row["risks_with_citation"] for row in rows)
    return {
        "cases": len(rows),
        "expected_risks": expected_total,
        "predicted_risks": predicted_total,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "exact_match_rate": round(divide(exact_match, len(rows)), 4),
        "citation_coverage": round(divide(citation_numerator, citation_denominator), 4),
        "abstention_recall": round(divide(abstention_correct, len(abstention_rows)), 4),
        "confident_error_cases": len(confident_error_rows),
    }


def evaluate_case(item: dict) -> dict:
    result = server.deterministic_analysis(
        text=item["text"],
        case_type="劳动合同",
        jurisdiction="全国规则",
    )
    expected = set(item["expected_risks"])
    predicted = {risk["id"] for risk in result["risks"]}
    true_positive = sorted(expected & predicted)
    false_positive = sorted(predicted - expected)
    false_negative = sorted(expected - predicted)
    return {
        "id": item["id"],
        "split": item["split"],
        "family": item["family"],
        "difficulty": item["difficulty"],
        "title": item["title"],
        "text": item["text"],
        "expected_risks": sorted(expected),
        "predicted_risks": sorted(predicted),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "expected_abstain": bool(item["expected_abstain"]),
        "predicted_abstain": bool(result["requiresHumanReview"]),
        "review_items": result["reviewItems"],
        "risk_level": result["riskLevel"],
        "predicted_risk_count": len(predicted),
        "risks_with_citation": sum(1 for risk in result["risks"] if risk["lawItems"]),
        "processing_ms": result["processingMs"],
    }


def render_markdown(report: dict) -> str:
    primary_name = "test" if "test" in report["metrics"] else "holdout"
    test = report["metrics"].get(primary_name, report["metrics"]["all"])
    all_metrics = report["metrics"]["all"]
    split_rows = [
        (name, metrics)
        for name, metrics in report["metrics"].items()
        if name != "all"
    ]
    lines = [
        "# 职安盾 V1.0 规则链评测报告",
        "",
        f"生成时间：{report['generated_at']}",
        "",
        f"> 本结果仅针对{len(report['cases'])}条团队合成样本，不代表真实用户分布，也不应被表述为最终法律准确性证明。",
        "",
        "## 测试集核心指标",
        "",
        "| 指标 | 数值 |",
        "|---|---:|",
        f"| 样本数 | {test['cases']} |",
        f"| 风险精确率 Precision | {test['precision']:.1%} |",
        f"| 风险召回率 Recall | {test['recall']:.1%} |",
        f"| 风险 F1 | {test['f1']:.1%} |",
        f"| 样本完全匹配率 | {test['exact_match_rate']:.1%} |",
        f"| 法源覆盖率 | {test['citation_coverage']:.1%} |",
        f"| 待核实召回率 | {test['abstention_recall']:.1%} |",
        f"| 应待核实却确定回答的样本 | {test['confident_error_cases']} |",
        "",
        "## 分数据集指标",
        "",
        "| 数据集 | Precision | Recall | F1 | 完全匹配 |",
        "|---|---:|---:|---:|---:|",
        *[
            f"| {name} | {metrics['precision']:.1%} | {metrics['recall']:.1%} | {metrics['f1']:.1%} | {metrics['exact_match_rate']:.1%} |"
            for name, metrics in split_rows
        ],
        f"| 全部 | {all_metrics['precision']:.1%} | {all_metrics['recall']:.1%} | {all_metrics['f1']:.1%} | {all_metrics['exact_match_rate']:.1%} |",
        "",
        "## 错误分布",
        "",
    ]
    for split in [primary_name, "all"]:
        errors = [row for row in report["cases"] if row["split"] == split and (row["false_positive"] or row["false_negative"])]
        lines.append(f"### {split}")
        lines.append("")
        if not errors:
            lines.append("无错误。")
            lines.append("")
            continue
        lines.append("| 样本 | 漏报 | 误报 |")
        lines.append("|---|---|---|")
        for row in errors:
            lines.append(f"| {row['id']} | {', '.join(row['false_negative']) or '-'} | {', '.join(row['false_positive']) or '-'} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--output-prefix", default="rules_v1_report")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows = [evaluate_case(item) for item in payload["cases"]]
    split_names = sorted({row["split"] for row in rows})
    report = {
        "system": "VeriWork rules+lexical-retrieval v1.0",
        "dataset_version": payload["version"],
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "metrics": {
            **{
                split_name: metric_block([row for row in rows if row["split"] == split_name])
                for split_name in split_names
            },
            "all": metric_block(rows),
        },
        "cases": rows,
    }
    json_path = RESULTS / f"{args.output_prefix}.json"
    md_path = RESULTS / f"{args.output_prefix}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    primary_name = "test" if "test" in report["metrics"] else "holdout"
    test = report["metrics"].get(primary_name, report["metrics"]["all"])
    print(f"Primary split: {primary_name}")
    print(f"Test cases: {test['cases']}")
    print(f"Precision: {test['precision']:.4f}")
    print(f"Recall: {test['recall']:.4f}")
    print(f"F1: {test['f1']:.4f}")
    print(f"Exact match: {test['exact_match_rate']:.4f}")
    print(f"Abstention recall: {test['abstention_recall']:.4f}")
    print(json_path)
    print(md_path)


if __name__ == "__main__":
    main()
