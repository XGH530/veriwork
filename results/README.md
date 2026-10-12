# 评测结果说明

- `rules_v1_report.md`：80条开发回归集结果。用于功能回归，不能宣称为真实用户准确率。
- `holdout_v1_hybrid_report.md`：32条早期留出集结果。该批数据暴露问题后曾用于一次规则强化，不再视为独立盲测。
- `frozen_holdout_v2_report.md`：40条冻结留出集结果。创建后未再针对该结果调规则，是当前最保守的规则链泛化结果。
- `deepseek_flash_pair_v1.md`：DeepSeek-Flash 同轮公平对照。
- `deepseek_v4_pro_pair_v1.md`：DeepSeek-V4-Pro 同轮公平对照；续费并使用断点续跑后，40条全部成功。

- `deepseek_flash_model_only.md` 和 `deepseek_flash_veriwork.md`：单独运行记录，不作为最严格的同轮对照。
- `dashboard_comparison.md`：所有可用结果的统一对比表。
- `llm_*.json/md`：使用 `tools/evaluate_llm.py` 接入大模型后生成，当前仓库不预置未实际运行的模型分数。

答辩时，必须把“开发集”“留出集”“真实用户测试”分别说明，不能混用。
