#!/usr/bin/env python3
"""汇总评测结果，生成答辩用对比表。"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

REPORTS = [
    ("rules_v1_report.json", "80条开发回归集", "规则+语义回退链", "同一批样本已参与规则开发，不能作为独立盲测"),
    ("holdout_v1_hybrid_report.json", "32条早期留出集", "规则+语义回退链", "暴露问题后用于规则强化，不再视为冻结留出集"),
    ("frozen_holdout_v2_report.json", "40条冻结留出集", "规则+语义回退链", "创建后不再针对结果调规则，是最保守的规则链泛化结果"),
]


def load_metrics(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["metrics"]["all"]


def main() -> None:
    rows = []
    for filename, dataset, system, note in REPORTS:
        path = RESULTS / filename
        if not path.exists():
            continue
        metrics = load_metrics(path)
        rows.append({
            "dataset": dataset,
            "system": system,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "exact_match_rate": metrics["exact_match_rate"],
            "abstention_recall": metrics["abstention_recall"],
            "note": note,
            "source": filename,
        })

    pair_sources = []
    for pair_path in sorted(RESULTS.glob("*_pair_v1.json")):
        pair = json.loads(pair_path.read_text(encoding="utf-8"))
        pair_sources.append(pair_path.name)
        failed = pair.get("failed_cases", 0)
        for key, label in (("model_only", "通用模型直答"), ("veriwork_hybrid", "职安盾混合链")):
            metrics = pair["systems"][key]["metrics"]["all"]
            note = f"公平对照；模型：{pair['model']}；法源覆盖 {metrics['citation_coverage']:.1%}"
            if failed:
                note += f"；成功{pair.get('successful_cases', '?')}条、失败{failed}条，仅报告成功样本"
            rows.append({
                "dataset": pair["dataset_version"],
                "system": label,
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "exact_match_rate": metrics["exact_match_rate"],
                "abstention_recall": metrics["abstention_recall"],
                "note": note,
                "source": pair_path.name,
            })

    known_sources = {item[0] for item in REPORTS}
    for path in sorted(RESULTS.glob("*.json")):
        if path.name in known_sources or path.name == "dashboard_comparison.json" or path.name == "deepseek_flash_pair_v1.json":
            continue
        if path.name in {"deepseek_flash_model_only.json", "deepseek_flash_veriwork.json"}:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not payload.get("model") or "metrics" not in payload:
            continue
        metrics = payload["metrics"]["all"]
        rows.append({
            "dataset": payload.get("dataset_version", "external"),
            "system": payload.get("system", path.stem),
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "exact_match_rate": metrics["exact_match_rate"],
            "abstention_recall": metrics["abstention_recall"],
            "note": f"模型：{payload.get('model', 'unknown')}",
            "source": path.name,
        })

    output = {"generated_from": "results/*.json", "rows": rows}
    json_path = RESULTS / "dashboard_comparison.json"
    md_path = RESULTS / "dashboard_comparison.md"
    json_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# 职安盾评测对比看板",
        "",
        "| 数据集 | 系统 | Precision | Recall | F1 | 完全匹配 | 待核实召回 | 说明 |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['dataset']} | {row['system']} | {row['precision']:.1%} | {row['recall']:.1%} | "
            f"{row['f1']:.1%} | {row['exact_match_rate']:.1%} | {row['abstention_recall']:.1%} | {row['note']} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(md_path)
    print(json_path)


if __name__ == "__main__":
    main()
