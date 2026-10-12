#!/usr/bin/env python3
"""创建不参与规则开发的独立留出集 V1。

该留出集在规则强化完成后创建，用于暴露泛化差距。运行一次后不得根据结果继续
针对性修改规则，否则它将不再具有留出集意义。
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "holdout_cases_v1.json"

RAW = [
    ("holdout_01", "入职后社保由员工自行购买，公司不承担费用", ["no_social_insurance"], False, "high"),
    ("holdout_02", "公司称试用期不办理社保，转正后再补缴", ["no_social_insurance"], False, "medium"),
    ("holdout_03", "被录用后需先交800元工装费才能上岗", ["employment_deposit"], False, "medium"),
    ("holdout_04", "公司要求上交毕业证原件代为保管", ["employment_deposit"], False, "hard"),
    ("holdout_05", "为获得岗位，需要先办理1万元技能提升贷款", ["training_loan"], False, "medium"),
    ("holdout_06", "岗前培训收费3000元，入职后从工资中扣除", ["training_loan"], False, "hard"),
    ("holdout_07", "试用期薪酬为约定工资的75%", ["probation_salary"], False, "medium"),
    ("holdout_08", "前三个月只发正式工资的一半", ["probation_salary"], False, "hard"),
    ("holdout_09", "劳动合同期限两年，约定试用期8个月", ["probation_duration"], False, "medium"),
    ("holdout_10", "公司表示表现好可提前转正，但试用期最长一年", ["probation_duration"], False, "easy"),
    ("holdout_11", "竞业禁止期三年，未约定任何补偿", ["noncompete_risk"], False, "medium"),
    ("holdout_12", "离开公司后24个月内不得同业，但每月无补偿", ["noncompete_risk"], False, "hard"),
    ("holdout_13", "工作日加班不计算加班工资", ["overtime_unpaid"], False, "medium"),
    ("holdout_14", "公司说绩效已覆盖所有额外工时，不再结算加班工资", ["overtime_unpaid"], False, "hard"),
    ("holdout_15", "未完成服务期离职，按剩余月份赔偿公司", ["resignation_penalty"], False, "hard"),
    ("holdout_16", "离职须经经理书面同意，否则扣发工资", ["resignation_penalty"], False, "medium"),
    ("holdout_17", "公司有权依业务变化调整员工岗位和薪资", ["unilateral_change"], False, "medium"),
    ("holdout_18", "工作地点可根据项目需要变更，员工不得异议", ["unilateral_change"], False, "hard"),
    ("holdout_19", "上月工资推迟到下月底发放", ["wage_delay"], False, "medium"),
    ("holdout_20", "离职后工资三个月后再发放", ["wage_delay"], False, "hard"),
    ("holdout_21", "公司先以试用协议代替劳动合同", ["no_written_contract"], False, "hard"),
    ("holdout_22", "毕业前先实习，入职满三个月后再签书面合同", ["no_written_contract"], False, "medium"),
    ("holdout_23", "社保先按最低档缴纳，转正后再调", ["social_base"], False, "medium"),
    ("holdout_24", "公司说按基本工资缴社保，不含绩效奖金", ["social_base"], False, "hard"),
    ("holdout_25", "岗位更倾向未婚女性", ["discrimination"], False, "hard"),
    ("holdout_26", "入职前签署不生育承诺书", ["discrimination"], False, "medium"),
    ("holdout_safe_27", "公司依法缴纳社会保险，不采用现金补贴", [], False, "easy"),
    ("holdout_safe_28", "公司不要求员工缴纳押金或提交证件原件", [], False, "medium"),
    ("holdout_safe_29", "合同期限三年以上，试用期约定六个月，工资按90%发放", [], False, "medium"),
    ("holdout_safe_30", "竞业限制两年并支付补偿，未扩大到普通员工", [], False, "medium"),
    ("holdout_review_31", "兼职主播合作协议，收入按平台分成", [], True, "hard"),
    ("holdout_review_32", "项目合作人员报酬按阶段结算，合作期限和社保尚未确定", [], True, "hard"),
]


def main() -> None:
    cases = []
    for case_id, text, expected, expected_abstain, difficulty in RAW:
        family = expected[0] if expected else ("review_required" if expected_abstain else "safe_control")
        cases.append({
            "id": case_id,
            "split": "holdout",
            "family": family,
            "title": family,
            "difficulty": difficulty,
            "text": text,
            "expected_risks": expected,
            "expected_abstain": expected_abstain,
            "source_type": "team_synthetic_holdout",
            "contains_personal_data": False,
            "review_status": "frozen_after_creation",
            "notes": "不参与规则开发；用于测量泛化差距。",
        })
    payload = {
        "version": "holdout-1.0.0",
        "created_on": "2026-10-08",
        "description": "32条独立留出样本，覆盖13类风险、安全对照和待核实场景。",
        "limitations": "仍为团队合成文本，不是经授权的真实用户数据。",
        "cases": cases,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} holdout cases")
    print(OUT)


if __name__ == "__main__":
    main()
