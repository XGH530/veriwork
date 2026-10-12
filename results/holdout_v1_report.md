# 职安盾 V1.0 规则链评测报告

生成时间：2026-10-08T14:42:54

> 本结果仅针对32条团队合成样本，不代表真实用户分布，也不应被表述为最终法律准确性证明。

## 测试集核心指标

| 指标 | 数值 |
|---|---:|
| 样本数 | 32 |
| 风险精确率 Precision | 100.0% |
| 风险召回率 Recall | 7.7% |
| 风险 F1 | 14.3% |
| 样本完全匹配率 | 25.0% |
| 法源覆盖率 | 100.0% |
| 待核实召回率 | 50.0% |
| 应待核实却确定回答的样本 | 1 |

## 分数据集指标

| 数据集 | Precision | Recall | F1 | 完全匹配 |
|---|---:|---:|---:|---:|
| holdout | 100.0% | 7.7% | 14.3% | 25.0% |
| 全部 | 100.0% | 7.7% | 14.3% | 25.0% |

## 错误分布

### holdout

| 样本 | 漏报 | 误报 |
|---|---|---|
| holdout_01 | no_social_insurance | - |
| holdout_03 | employment_deposit | - |
| holdout_04 | employment_deposit | - |
| holdout_05 | training_loan | - |
| holdout_06 | training_loan | - |
| holdout_07 | probation_salary | - |
| holdout_08 | probation_salary | - |
| holdout_09 | probation_duration | - |
| holdout_11 | noncompete_risk | - |
| holdout_12 | noncompete_risk | - |
| holdout_13 | overtime_unpaid | - |
| holdout_14 | overtime_unpaid | - |
| holdout_15 | resignation_penalty | - |
| holdout_16 | resignation_penalty | - |
| holdout_17 | unilateral_change | - |
| holdout_18 | unilateral_change | - |
| holdout_19 | wage_delay | - |
| holdout_20 | wage_delay | - |
| holdout_21 | no_written_contract | - |
| holdout_22 | no_written_contract | - |
| holdout_23 | social_base | - |
| holdout_24 | social_base | - |
| holdout_25 | discrimination | - |
| holdout_26 | discrimination | - |

### all

无错误。

