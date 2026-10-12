#!/usr/bin/env python3
"""生成职安盾 V1.0 评测集。

数据全部为团队基于公开规则构造的合成文本，不含真实个人信息，不宣称等同于
真实用户分布。脚本用于保证样本可复现、标签可审计，正式参赛前仍需由法律实务
人员抽样复核，并补充经过授权的匿名真实案例。
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

RISK_VARIANTS = {
    "no_social_insurance": [
        "公司提出每月额外补800元，由员工自愿放弃社会保险。",
        "入职后不缴纳社保，改为发放社保补贴。",
        "乙方确认无需公司办理社会保险，相关责任自行承担。",
        "试用期不购买社保，转正后再考虑是否办理。",
    ],
    "employment_deposit": [
        "新员工入职时需缴纳2000元设备押金，离职时视情况返还。",
        "员工须统一缴纳1000元履约保证金，方可办理入职。",
        "员工身份证原件由公司保管，离职手续办完后归还。",
        "入职需交服装费500元，工作满一年后退还。",
    ],
    "training_loan": [
        "公司要求毕业生通过分期贷款支付岗前培训费。",
        "入职前先交9800元培训费，工作满一年后返还。",
        "无经验员工需办理培训贷，由公司指定平台完成。",
        "工作未满两年离职，需偿还公司介绍的培训贷款。",
    ],
    "probation_salary": [
        "试用期工资为转正工资的70%，转正后另行调整。",
        "试用期薪资按正式员工工资的50%发放。",
        "试用期工资60%，绩效奖金另行考核。",
        "试用期月薪为合同约定工资的60%，不享受正式员工福利。",
    ],
    "probation_duration": [
        "合同期限一年，试用期六个月，期满后再决定是否录用。",
        "公司将试用期延长至六个月，并保留再次考核的权利。",
        "转正后仍需再次试用三个月，合格后才能享受正式待遇。",
        "劳动合同约定试用期6个月后转正，考核不合格不录用。",
    ],
    "noncompete_risk": [
        "离职后三年内不得从事同类业务，公司不另行支付补偿。",
        "竞业限制期限为三年，且公司无需支付经济补偿。",
        "竞业限制期内不支付经济补偿，员工仍应履行限制义务。",
        "离职后3年内不得进入同行业公司，限制范围不限地域。",
    ],
    "overtime_unpaid": [
        "公司实行996工作制，员工不得主张加班费。",
        "因工作需要延长工作时间，视为员工自愿加班。",
        "加班费已包含在基本工资中，不再另行计算。",
        "员工自愿放弃加班费，并承诺不因工时问题提出异议。",
    ],
    "resignation_penalty": [
        "员工未满一年辞职需支付违约金10000元。",
        "离职需提前三个月提出并经公司批准，否则视为违约。",
        "员工辞职要交违约金20000元，用于弥补招聘成本。",
        "服务期未满三年离职需支付违约金，并扣发剩余工资。",
    ],
    "unilateral_change": [
        "公司可根据经营需要随时调岗调薪，员工应予配合。",
        "员工须无条件服从调岗，不得拒绝新的工作安排。",
        "公司根据经营需要调整工作地点，无需征得员工同意。",
        "公司可随时调整岗位和薪酬，员工无条件服从。",
    ],
    "wage_delay": [
        "公司实行押一个月工资制度，离职时统一结算。",
        "每月工资于次月30日前发放，遇节假日顺延。",
        "年度奖金和绩效工资年底统一发放。",
        "离职后满两个月再结算剩余工资。",
    ],
    "no_written_contract": [
        "公司仅口头约定薪资和工作时间，暂不签订劳动合同。",
        "试用期不签合同，转正后再签订劳动合同。",
        "入职后暂不签订劳动合同，待部门确认后再补。",
        "转正后才签订劳动合同，试用期内不办理书面文件。",
    ],
    "social_base": [
        "不论实际工资多少，社保按最低基数缴纳。",
        "工资拆分为基本工资和社保补贴，社保按最低标准缴纳。",
        "公司统一按最低基数办理社保，不按实际工资申报。",
        "社保按最低标准缴纳，差额通过现金补贴发放。",
    ],
    "discrimination": [
        "招聘简章写明仅限男性，女性不考虑。",
        "女性入职需承诺三年内不怀孕。",
        "同等条件下男性优先，已婚未育女性暂不考虑。",
        "入职需承诺五年内不结婚生育，否则不予录用。",
    ],
}

SAFE_VARIANTS = [
    "公司依法为员工缴纳社会保险，不提供社保补贴替代。",
    "公司不收取任何押金、保证金，也不扣押员工证件。",
    "公司不要求员工参加培训贷，也不设置任何岗前收费。",
    "试用期工资为约定工资的85%，且不低于当地最低工资标准。",
    "合同期限三年，试用期六个月，试用期工资为约定工资的90%。",
    "竞业限制期限为两年，公司按月支付经济补偿。",
    "因工作需要安排加班，公司依法支付加班费或安排调休。",
    "员工提前三十日书面通知即可解除劳动合同，无需支付违约金。",
    "岗位、薪酬和工作地点调整需双方协商一致并书面确认。",
    "工资每月十五日前以货币形式足额支付。",
    "公司自用工之日起一个月内与员工签订书面劳动合同。",
    "公司按员工实际工资申报社保缴费基数并足额缴纳。",
    "招聘不限制性别、婚育状况和地域。",
    "加班可安排调休，不能调休时依法支付加班费。",
    "劳动合同为无固定期限，试用期不超过六个月。",
    "公司不会以任何名义收取押金、保证金或培训费用。",
]

REVIEW_VARIANTS = [
    "实习生与公司签订实习协议，不建立劳动关系，但工作内容和考勤由部门统一管理。",
    "兼职人员按任务结算报酬，不适用全职员工排班制度。",
    "双方签订劳务合作协议，期限一年，服务费按月结算。",
    "非全日制用工，每日工作四小时，每周工作时间累计不超过二十四小时。",
    "劳动合同期限以实际项目周期为准，工资面议。",
    "试用期待定，转正后确定薪资，社保另行沟通。",
    "社保缴纳方案另行约定，目前尚未写入合同。",
    "HR口头表示试用期三个月，但暂未写入合同。",
    "公司口头承诺试用期工资不低于正式工资的80%，微信里说，暂未写入合同。",
    "工资包含绩效，具体计算以实际为准。",
    "实习补贴面议，公司称可转正后签订劳动合同。",
    "灵活用工合作协议，报酬面议，社保未明确。",
]

TITLES = {
    "no_social_insurance": "放弃或未依法缴纳社保",
    "employment_deposit": "押金、保证金与证件扣押",
    "training_loan": "培训贷与岗前收费",
    "probation_salary": "试用期工资低于底线",
    "probation_duration": "试用期期限异常",
    "noncompete_risk": "竞业限制期限或补偿异常",
    "overtime_unpaid": "无偿加班或排除加班费",
    "resignation_penalty": "辞职违约金与离职限制",
    "unilateral_change": "单方调岗调薪",
    "wage_delay": "工资延迟或拖欠",
    "no_written_contract": "不签或拖延书面合同",
    "social_base": "社保基数或缴纳方式异常",
    "discrimination": "性别婚育就业歧视",
}


def make_case(case_id: str, split: str, family: str, text: str, expected: list[str], *, difficulty: str = "easy", expected_abstain: bool = False, notes: str = "") -> dict:
    return {
        "id": case_id,
        "split": split,
        "family": family,
        "title": TITLES.get(family, family),
        "difficulty": difficulty,
        "text": text,
        "expected_risks": expected,
        "expected_abstain": expected_abstain,
        "source_type": "team_synthetic_from_public_rules",
        "contains_personal_data": False,
        "review_status": "pending_legal_sample_review",
        "notes": notes,
    }


def build_cases() -> list[dict]:
    cases: list[dict] = []
    difficulty_by_variant = ["easy", "easy", "medium", "hard"]

    for family, variants in RISK_VARIANTS.items():
        for index, text in enumerate(variants):
            split = "development" if index < 2 else "test"
            cases.append(make_case(
                f"{family}_{index + 1:02d}",
                split,
                family,
                text,
                [family],
                difficulty=difficulty_by_variant[index],
                notes="规则命中样例；参加正式测试前需人工复核标签。",
            ))

    for index, text in enumerate(SAFE_VARIANTS):
        split = "development" if index < 8 else "test"
        difficulty = "medium" if index >= 8 else "easy"
        cases.append(make_case(
            f"safe_{index + 1:02d}",
            split,
            "safe_control",
            text,
            [],
            difficulty=difficulty,
            notes="安全对照样例；其中包含否定表达和边界条件。",
        ))

    for index, text in enumerate(REVIEW_VARIANTS):
        split = "development" if index < 6 else "test"
        difficulty = "hard"
        cases.append(make_case(
            f"review_{index + 1:02d}",
            split,
            "review_required",
            text,
            [],
            difficulty=difficulty,
            expected_abstain=True,
            notes="信息不足或关系性质不明，系统应提示人工核实而不是给出确定结论。",
        ))

    return cases


def main() -> None:
    cases = build_cases()
    if len(cases) != 80:
        raise RuntimeError(f"Expected 80 cases, got {len(cases)}")

    json_path = DATA_DIR / "evaluation_cases_v1.json"
    csv_path = DATA_DIR / "evaluation_cases_v1.csv"
    summary_path = DATA_DIR / "evaluation_dataset_summary.md"

    json_path.write_text(json.dumps({
        "version": "1.0.0",
        "created_on": "2026-10-08",
        "description": "80条合成评测样本，覆盖13类风险、16条安全对照和12条待核实边界样例。",
        "limitations": "全部为团队合成文本，不含真实个人信息，不能替代经授权的真实用户盲测。",
        "cases": cases,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "id", "split", "family", "title", "difficulty", "text",
            "expected_risks", "expected_abstain", "source_type",
            "contains_personal_data", "review_status", "notes",
        ])
        writer.writeheader()
        for item in cases:
            row = dict(item)
            row["expected_risks"] = "|".join(item["expected_risks"])
            writer.writerow(row)

    counts = Counter(item["family"] for item in cases)
    split_counts = Counter(item["split"] for item in cases)
    difficulty_counts = Counter(item["difficulty"] for item in cases)
    summary = [
        "# 职安盾评测集 V1.0",
        "",
        f"- 样本总数：{len(cases)}",
        f"- 开发集：{split_counts['development']}",
        f"- 测试集：{split_counts['test']}",
        f"- 简单样本：{difficulty_counts['easy']}",
        f"- 中等样本：{difficulty_counts['medium']}",
        f"- 困难样本：{difficulty_counts['hard']}",
        f"- 含风险标签样本：{sum(1 for item in cases if item['expected_risks'])}",
        f"- 安全对照样本：{counts['safe_control']}",
        f"- 待核实样本：{counts['review_required']}",
        "",
        "## 数据边界",
        "",
        "当前数据全部为团队合成的公开规则样例，不含真实个人信息。其作用是验证系统链路、发现规则冲突和建立可复现实验流程，不等同于真实用户分布。正式参赛前应邀请法律实务人员抽样复核，并在合法授权与去标识化前提下补充真实案例。",
        "",
        "## 类别分布",
        "",
        "| 类别 | 数量 |",
        "|---|---:|",
    ]
    for family, count in sorted(counts.items()):
        summary.append(f"| {family} | {count} |")
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")

    print(f"Generated {len(cases)} cases")
    print(json_path)
    print(csv_path)
    print(summary_path)


if __name__ == "__main__":
    main()
