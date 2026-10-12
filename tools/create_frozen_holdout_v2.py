#!/usr/bin/env python3
"""创建冻结留出集 V2。

V2 在语义层开发完成后创建。运行后不得依据结果继续修改规则，只能用于报告
泛化差距和指导下一轮模型实验。
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "holdout_cases_v2_frozen.json"

RAW = [
    ("frozen_001", "公司提出社保费用由个人全部承担，单位只发现金补贴。", ["no_social_insurance"], False, "medium"),
    ("frozen_002", "约定试用期内员工自行缴纳社会保险，公司不办理参保。", ["no_social_insurance"], False, "easy"),
    ("frozen_003", "入职材料中要求上交毕业证书原件，由人事统一保管。", ["employment_deposit"], False, "medium"),
    ("frozen_004", "转正前需支付1000元工牌和设备保证金。", ["employment_deposit"], False, "easy"),
    ("frozen_005", "零基础求职者被要求办理两万元技能培训分期。", ["training_loan"], False, "medium"),
    ("frozen_006", "岗前课程收费4800元，费用入职后从工资扣除。", ["training_loan"], False, "hard"),
    ("frozen_007", "试岗期只按约定工资的65%支付。", ["probation_salary"], False, "hard"),
    ("frozen_008", "试用期按合同工资的78%结算。", ["probation_salary"], False, "medium"),
    ("frozen_009", "一年期合同设置三个月试用期。", ["probation_duration"], False, "medium"),
    ("frozen_010", "合同写两年，试用期四个月。", ["probation_duration"], False, "easy"),
    ("frozen_011", "离职后两年内不得同业，合同没有补偿条款。", ["noncompete_risk"], False, "hard"),
    ("frozen_012", "禁止参与竞业两年，但不给补偿。", ["noncompete_risk"], False, "hard"),
    ("frozen_013", "非工作时间处理工作，被认定为不计薪工时。", ["overtime_unpaid"], False, "hard"),
    ("frozen_014", "法定节假日值班，公司以调休替代全部加班工资。", ["overtime_unpaid"], False, "hard"),
    ("frozen_015", "合同期内辞职需要向公司赔偿三个月工资。", ["resignation_penalty"], False, "medium"),
    ("frozen_016", "未到服务期离开，按未履行年限缴纳赔偿金。", ["resignation_penalty"], False, "medium"),
    ("frozen_017", "公司可按业务需要调整岗位，员工不得提出异议。", ["unilateral_change"], False, "medium"),
    ("frozen_018", "办公地点随项目变化，员工须接受安排。", ["unilateral_change"], False, "hard"),
    ("frozen_019", "上月工资延后至下下月发放。", ["wage_delay"], False, "medium"),
    ("frozen_020", "离职后工资分三期发放。", ["wage_delay"], False, "hard"),
    ("frozen_021", "公司先用试用协议替代书面劳动合同。", ["no_written_contract"], False, "medium"),
    ("frozen_022", "入职三个月后补签劳动合同。", ["no_written_contract"], False, "hard"),
    ("frozen_023", "社保按最低档缴纳。", ["social_base"], False, "easy"),
    ("frozen_024", "社保缴费基数只按底薪计算。", ["social_base"], False, "hard"),
    ("frozen_025", "招聘要求三年内无生育计划。", ["discrimination"], False, "medium"),
    ("frozen_026", "此岗位更希望招未婚男性。", ["discrimination"], False, "hard"),
    ("frozen_safe_027", "员工可依法参保，公司不通过现金替代。", [], False, "easy"),
    ("frozen_safe_028", "入职流程不收费，也不扣押任何证件。", [], False, "medium"),
    ("frozen_safe_029", "合同两年，试用期两个月，工资为约定工资的85%。", [], False, "medium"),
    ("frozen_safe_030", "竞业限制一年，按季度支付补偿。", [], False, "medium"),
    ("frozen_safe_031", "加班按规定安排调休或者支付加班费。", [], False, "easy"),
    ("frozen_safe_032", "书面劳动合同在入职一个月内签订。", [], False, "easy"),
    ("frozen_safe_033", "岗位调整由双方协商并签署补充协议。", [], False, "medium"),
    ("frozen_safe_034", "公司按实际工资申报社保缴费基数。", [], False, "medium"),
    ("frozen_review_035", "平台骑手合作协议，报酬按单结算，是否建立劳动关系未明确。", [], True, "hard"),
    ("frozen_review_036", "毕业前实习，毕业后视考核决定是否转正。", [], True, "medium"),
    ("frozen_review_037", "兼职内容审核，每周排班由平台安排。", [], True, "medium"),
    ("frozen_review_038", "项目制合作，费用和纳税方式尚未确定。", [], True, "hard"),
    ("frozen_review_039", "公司说工资由基本工资和绩效构成，具体比例待定。", [], True, "hard"),
    ("frozen_review_040", "口头承诺有年终奖，但合同未写。", [], True, "medium"),
]


def main() -> None:
    cases = []
    for case_id, text, expected, expected_abstain, difficulty in RAW:
        family = expected[0] if expected else ("review_required" if expected_abstain else "safe_control")
        cases.append({
            "id": case_id,
            "split": "frozen_holdout",
            "family": family,
            "title": family,
            "difficulty": difficulty,
            "text": text,
            "expected_risks": expected,
            "expected_abstain": expected_abstain,
            "source_type": "team_synthetic_frozen_holdout",
            "contains_personal_data": False,
            "review_status": "frozen_no_rule_tuning_allowed",
            "notes": "V2冻结留出集；仅运行一次，不根据结果继续调规则。",
        })
    payload = {
        "version": "holdout-v2.0.0-frozen",
        "created_on": "2026-10-08",
        "description": "40条冻结留出样本，用于报告混合规则链的真实泛化差距。",
        "limitations": "团队合成文本，不是真实用户数据；不能替代外部盲测。",
        "cases": cases,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} frozen holdout cases")
    print(OUT)


if __name__ == "__main__":
    main()
