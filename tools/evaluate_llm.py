#!/usr/bin/env python3
"""OpenAI-compatible 大模型对照评测。

支持两种模式：
1. 纯通用模型：让模型直接判断风险。
2. 职安盾混合链：模型判断与确定性规则取并集，引用只采用本地法源映射。

示例：
python tools/evaluate_llm.py --dataset data/holdout_cases_v2_frozen.json \
  --model qwen-plus --api-url https://example/v1/chat/completions \
  --api-key-env LLM_API_KEY --output-prefix qwen_holdout_v2

未提供 API 时使用 --dry-run 只生成提示词样例，不发送网络请求。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from tools.evaluate_rules import metric_block, render_markdown  # noqa: E402

RESULTS = ROOT / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

RISK_IDS = [risk["id"] for risk in server.RISKS]
RISK_TITLES = {risk["id"]: risk["title"] for risk in server.RISKS}


def build_prompt(text: str) -> str:
    return (
        "你是就业合同风险识别器。只允许从以下风险ID中选择，不得创造新ID：\n"
        f"{', '.join(RISK_IDS)}\n\n"
        "请判断给定文本中明确存在或高度可能存在哪些风险。信息不足时 abstain=true，"
        "不要作确定结论。返回严格 JSON："
        '{"risks":["风险ID"],"abstain":false,"confidence":0.0,'
        '"evidence":[{"id":"风险ID","clause":"原文片段","reason":"不超过80字"}]}。\n\n'
        f"待分析文本：\n{text}"
    )


def parse_json_object(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        content = content.removeprefix("```json").removeprefix("```")
        content = content.removesuffix("```").strip()
    start = content.find("{")
    end = content.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("模型未返回JSON对象")
    return json.loads(content[start:end + 1])


def call_model(api_url: str, api_key: str, model: str, text: str, temperature: float, timeout: int) -> dict:
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": "你是严格、保守的就业合同风险识别器。"},
            {"role": "user", "content": build_prompt(text)},
        ],
    }
    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    content = body["choices"][0]["message"]["content"]
    return parse_json_object(content)


def evaluate_case(
    item: dict,
    *,
    api_url: str,
    api_key: str,
    model: str,
    temperature: float,
    timeout: int,
    combine_rules: bool,
) -> dict:
    started = time.perf_counter()
    model_result = call_model(api_url, api_key, model, item["text"], temperature, timeout)
    model_risks = {risk_id for risk_id in model_result.get("risks", []) if risk_id in RISK_IDS}
    model_abstain = bool(model_result.get("abstain", False))

    rule_result = server.deterministic_analysis(item["text"], "劳动合同", "全国规则")
    rule_risks = {risk["id"] for risk in rule_result["risks"]}
    predicted = model_risks | rule_risks if combine_rules else model_risks
    predicted_abstain = model_abstain or (rule_result["requiresHumanReview"] if combine_rules else False)

    expected = set(item["expected_risks"])
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
        "model_risks": sorted(model_risks),
        "rule_risks": sorted(rule_risks),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "expected_abstain": bool(item["expected_abstain"]),
        "predicted_abstain": predicted_abstain,
        "review_items": rule_result["reviewItems"],
        "risk_level": rule_result["riskLevel"],
        "predicted_risk_count": len(predicted),
        "risks_with_citation": len(predicted) if combine_rules else 0,
        "processing_ms": max(1, round((time.perf_counter() - started) * 1000)),
        "raw_model_result": model_result,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(ROOT / "data" / "holdout_cases_v2_frozen.json"))
    parser.add_argument("--api-url", default=os.environ.get("LLM_API_URL", ""))
    parser.add_argument("--api-key-env", default="LLM_API_KEY")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", "model-name"))
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--output-prefix", default="llm_comparison")
    parser.add_argument("--model-only", action="store_true", help="只评估通用模型，不合并规则结果")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    payload = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    items = payload["cases"]
    if args.limit:
        items = items[:args.limit]

    if args.dry_run:
        print(json.dumps({
            "model": args.model,
            "dataset": str(Path(args.dataset)),
            "cases": len(items),
            "prompt_example": build_prompt(items[0]["text"]),
        }, ensure_ascii=False, indent=2))
        return

    api_key = os.environ.get(args.api_key_env, "")
    if not args.api_url or not api_key:
        raise SystemExit(f"缺少 --api-url 或环境变量 {args.api_key_env}")

    rows = []
    for index, item in enumerate(items, start=1):
        print(f"[{index}/{len(items)}] {item['id']}")
        try:
            rows.append(evaluate_case(
                item,
                api_url=args.api_url,
                api_key=api_key,
                model=args.model,
                temperature=args.temperature,
                timeout=args.timeout,
                combine_rules=not args.model_only,
            ))
        except (urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as exc:
            rows.append({
                "id": item["id"],
                "split": item["split"],
                "family": item["family"],
                "difficulty": item["difficulty"],
                "title": item["title"],
                "text": item["text"],
                "expected_risks": item["expected_risks"],
                "predicted_risks": [],
                "true_positive": [],
                "false_positive": [],
                "false_negative": item["expected_risks"],
                "expected_abstain": item["expected_abstain"],
                "predicted_abstain": False,
                "review_items": [],
                "risk_level": "error",
                "predicted_risk_count": 0,
                "risks_with_citation": 0,
                "processing_ms": 0,
                "error": f"{type(exc).__name__}: {exc}",
            })

    errors = [row for row in rows if row.get("error")]
    valid_rows = [row for row in rows if not row.get("error")]
    if not valid_rows:
        raise SystemExit(f"所有 {len(rows)} 个请求均失败，未生成模型成绩。首个错误：{errors[0].get('error') if errors else 'unknown'}")

    split_names = sorted({row["split"] for row in valid_rows})
    report = {
        "system": f"LLM {'model-only' if args.model_only else 'VeriWork hybrid'}",
        "model": args.model,
        "dataset_version": payload["version"],
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "successful_cases": len(valid_rows),
        "failed_cases": len(errors),
        "errors": [{"id": row["id"], "error": row.get("error")} for row in errors],
        "metrics": {
            **{name: metric_block([row for row in valid_rows if row["split"] == name]) for name in split_names},
            "all": metric_block(valid_rows),
        },
        "cases": rows,
    }
    json_path = RESULTS / f"{args.output_prefix}.json"
    md_path = RESULTS / f"{args.output_prefix}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    print(json_path)
    print(md_path)


if __name__ == "__main__":
    main()
