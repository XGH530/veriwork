#!/usr/bin/env python3
"""创建地方政策包草案。

由于动态数字标准必须核验官方最新文件，草案不填入未经确认的数值。正式提交前
必须通过 tools/validate_policy_pack.py --strict，并记录核验人和官方来源。
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "jurisdiction_policy_pack_draft.json"

REGIONS = {
    "全国规则": ("全国基础规则包", "全国人大法律法规数据库", "https://flk.npc.gov.cn/"),
    "北京": ("北京地区政策适配包", "北京市人力资源和社会保障局", "https://rsj.beijing.gov.cn/"),
    "上海": ("上海地区政策适配包", "上海市人力资源和社会保障局", "https://rsj.sh.gov.cn/"),
    "广东": ("广东地区政策适配包", "广东省人力资源和社会保障厅", "https://hrss.gd.gov.cn/"),
}

POLICIES = [
    ("minimum_wage", "月最低工资标准", "CNY/month"),
    ("social_insurance_base", "社会保险缴费基数口径", "policy_rule"),
    ("labor_inspection_guide", "劳动保障监察投诉办事指南", "policy_rule"),
]


def main() -> None:
    profiles = []
    for region, (title, source_name, source_url) in REGIONS.items():
        entries = []
        for policy_id, policy_name, unit in POLICIES:
            entries.append({
                "policy_id": policy_id,
                "name": policy_name,
                "value": None,
                "unit": unit,
                "effective_from": None,
                "source_name": source_name,
                "source_url": source_url,
                "status": "pending_official_verification",
                "verified_at": None,
                "verified_by": None,
                "notes": "必须使用官方最新文件核验数值、生效日期和适用地域。",
            })
        profiles.append({
            "jurisdiction": region,
            "title": title,
            "coverage": "全市" if region in {"北京", "上海"} else ("省级规则，城市标准需细分" if region == "广东" else "全国"),
            "version": "draft-1.0.0",
            "last_checked": "2026-10-08",
            "policies": entries,
        })
    payload = {
        "schema_version": "1.0",
        "package_version": "draft-1.0.0",
        "created_on": "2026-10-08",
        "status": "draft_pending_official_verification",
        "warning": "禁止在未核验的情况下把草案数值用于正式风险结论。",
        "profiles": profiles,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
