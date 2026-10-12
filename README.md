# 职安盾 VeriWork

> 面向高校毕业生就业合同的可验证 AI 风险评估与证据链系统

## 项目定位

“职安盾”不是法律问答机器人，而是面向就业合同、实习协议和招聘材料的可信决策系统。系统把确定性规则、语义识别、有出处的地方政策与大模型解释组合起来，输出可追溯的风险结论、证据清单和行动方案。

核心目标：**让每一条风险结论都有依据、有证据、有下一步；没有依据时能够拒答。**

## 当前状态

- 可运行前端演示与标准库后端服务。
- 13类风险规则、语义回退层、法源检索、待核实与拒答机制。
- 80条开发回归集、32条早期留出集、40条冻结留出集。
- 支持 OpenAI-compatible 模型对照评测。
- 提供答辩 PPT、三分钟演示脚本、评测方案和提交冲刺清单。
- 地方政策包已建结构，但数值必须由团队核验官方原文后填入。

## 核心能力

1. **可信研判链**：规则引擎负责硬约束，法源检索提供依据，大模型负责长尾语义，校验器负责拒答与复核。
2. **证据闭环**：从风险识别延伸到证据保存、时间线、沟通问题、投诉材料和办理路径。
3. **量化验证**：记录风险精确率、召回率、F1、法源覆盖率和待核实召回率。
4. **隐私与合规**：原始材料默认不长期保存，禁止把未经授权的真实合同放入公开材料。

## 用户登录

后端模式使用SQLite用户系统和Bearer会话令牌。系统首次启动会自动创建演示账号：

- 学生演示：`demo / demo123456`
- 管理员演示：`admin / admin123456`
- 管理员可访问“管理后台”，查看用户、研判次数、高频风险和角色管理

用户也可以注册自己的账号。未登录用户可以浏览页面和运行纯前端演示，但后端合同研判和PDF/Word解析需要登录。密码使用PBKDF2-SHA256加盐存储，API密钥不会进入浏览器。

## 政策服务

系统新增“政策服务”页面，根据身份、地区、就业状态和需求匹配国家就业政策框架，输出支持内容、初步条件、材料清单、办理渠道和官方来源。地方金额、对象和截止时间统一标记为待属地核验，不写死未经验证的地方标准。

## 在线演示

- 演示地址：http://8.133.222.0/veriwork/
- GitHub：https://github.com/XGH530/veriwork

## 运行方式

### 纯前端演示

直接打开 `index.html`，或双击 `启动前端演示.bat`。无需安装依赖。

### 安装文件解析依赖

支持PDF和Word上传需要安装可选依赖：

```bash
python -m pip install -r requirements.txt
```

### 完整本地服务

需要 Python 3.10 及以上：

```bash
python server.py
```

访问 `http://127.0.0.1:8000`。服务端只使用 Python 标准库，不需要安装依赖。

### 接入大模型

复制 `.env.example` 为 `.env` 并填写，或使用环境变量：

```powershell
$env:LLM_API_URL="https://你的模型服务地址/v1/chat/completions"
$env:LLM_API_KEY="你的密钥"
$env:LLM_MODEL="模型名称"
python server.py
```

模型只负责在已识别风险和法源范围内解释，不能修改风险等级或新增法源。

## 评测命令

生成80条开发回归集：

```bash
python tools/generate_dataset.py
```

运行规则与语义回退链评测：

```bash
python tools/evaluate_rules.py
python tools/evaluate_rules.py --dataset data/holdout_cases_v2_frozen.json --output-prefix frozen_holdout_v2_report
```

运行后建议使用同轮公平对照脚本：

```bash
python tools/evaluate_llm_pair.py \
  --dataset data/holdout_cases_v2_frozen.json \
  --output-prefix model_pair
```

单独运行大模型对照实验：

```bash
python tools/evaluate_llm.py \
  --dataset data/holdout_cases_v2_frozen.json \
  --model 模型名称 \
  --api-url https://你的模型服务/v1/chat/completions \
  --api-key-env LLM_API_KEY \
  --output-prefix model_a_holdout_v2
```

汇总全部结果：

```bash
python tools/build_comparison.py
```

## 一键检查

提交前运行：

```bash
python tools/run_checks.py
```

该脚本会依次执行服务端语法检查、后端单元测试、开发回归、冻结留出集报告、政策包校验、结果汇总和前端冒烟测试。
## 测试

浏览器端：打开 `tests.html`，当前10个基础风险场景全部通过。

服务端：

```bash
python -m unittest discover -s tests -v
python tools/validate_policy_pack.py
```

## 关键文件

```text
职安盾-VeriWork/
├─ index.html                         产品前端
├─ presentation.html                  答辩演示
├─ app.js / styles.css                前端逻辑与样式
├─ data.js                            规则、法源和演示案例
├─ server.py                          本地服务与大模型适配
├─ data/                              评测集、政策包和官方来源
├─ Dockerfile / render.yaml           公网部署文件
├─ submission/                        竞赛提交材料模板
├─ results/                           自动生成的评测报告
├─ tools/                             数据集、评测和校验脚本
├─ tests/                             后端单元测试
└─ docs/
   ├─ 竞赛规则与流程总览.md
   ├─ 零基础系统说明书.md
   ├─ 省级赛答辩提纲.md
   ├─ 三分钟演示脚本.md
   ├─ 评测方案.md
   ├─ 数据与隐私治理.md
   └─ 省赛提交冲刺清单.md
```

## 官方来源与部署

部署配置文件位于 `deploy/`：

- `deploy/veriwork.nginx.conf`：Nginx子路径反向代理；
- `deploy/veriwork.service`：systemd常驻服务；
- `deploy/update-from-github.sh`：从GitHub一键拉取更新并重启。

官方法规和最低工资数据保存在 `data/official_sources/`，包含原始HTML、正文、来源URL和SHA-256。公网部署说明见 `docs/公网部署指南.md`，Docker和Render配置已包含在项目根目录。
## 重要边界

当前评测集全部为团队合成文本，不含真实个人信息，也不是经授权的真实用户盲测。冻结留出集用于揭示泛化差距，不得通过继续调规则来“刷分”。正式提交前应完成多模型对照、20名以上用户测试、法律实务人员抽样复核和地方政策核验。

本系统用于竞赛展示、普法教育和材料整理，不替代律师、仲裁机构或人社部门作出最终法律判断。若使用生成式 AI，应按竞赛要求完整披露工具名称、使用环节、工作流、人工筛选修改过程和团队原创贡献。
