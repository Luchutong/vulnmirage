# VulnMirage：面向代码审计 Agent 的仓库上下文注入 Benchmark

<div align="center">

**用于评测仓库上下文注入如何影响 Agent 的漏洞发现、验证、严重性判断与最终安全审计报告。**

[English](README.md) | [简体中文](README_CN.md)

[代码仓库](https://github.com/xinyi234/vulnmirage) ·
[Benchmark 设计](docs/benchmark_revision_plan_2026-11-03.md) ·
[下一阶段路线图](docs/next_stage_design_2026-11-04.md) ·
[实验流程](docs/campaign.md) ·
[WSL 部署](docs/wsl_deployment.md) ·
[Payload 方法](PayloadGen/README.md)

</div>

---

## 最新进展

- **2026-11-12**：增加 WSL/Linux 原生 OpenCode 2.x 配置、rootless network
  namespace、Unix-socket inference gateway、OpenCode 2.2.7 trace fixture 和完整
  WSL 部署说明。
- **2026-11-11**：建立规范攻击分类，将攻击目标、方法、载体表面、I0–I4 强度和
  realization 分离；三个核心 O-FN 方法具备完整强度梯度。
- **2026-11-04**：将“预先克隆全部仓库”的旧流程改为逐任务流式实验：下载一个
  精确快照、注入、审计、归档、清理，再处理下一个任务。
- **2026-11-03**：引入 dataset-core 边界、独立 verifier、报告/结构化 finding
  双输出、泄露控制和机制分析产物。

## 目录

- [项目简介](#项目简介)
- [Benchmark 概览](#benchmark-概览)
- [核心设计](#核心设计)
- [生成能力与攻击分类](#生成能力与攻击分类)
- [Variant sets](#variant-sets)
- [数据资源](#数据资源)
- [安装](#安装)
- [快速开始](#快速开始)
- [评测指标与产物](#评测指标与产物)
- [当前进度](#当前进度)
- [路线图](#路线图)
- [项目结构](#项目结构)
- [引用](#引用)
- [许可证](#许可证)

## 项目简介

安全审计 Agent 不只读取源代码，还会接触代码注释、README、安全说明、辅助文件、
看似可信的工具输出、严重性声明，以及“看起来有漏洞但实际上安全”的诱饵代码。
VulnMirage 用于测量这些仓库内信号是否会改变 Agent 对同一个真实漏洞快照的判断。

核心实验采用配对设计：

```text
同一任务 + 同一精确 commit + 同一审计 prompt + 同一模型与预算
                         │
                         ├── C：干净仓库
                         └── A：独立生成的注入仓库
                                      ↓
                  结果差异 + 报告差异 + 可观测轨迹差异
```

VulnMirage 当前是 benchmark 实现与实验 harness，不是已发布的排行榜。核心评测
流程稳定前暂不引入防御条件；干净仓库 `C` 是唯一 baseline，也不加入中性内容注入。

## Benchmark 概览

| 组成 | 当前数量 |
| :-- | --: |
| 精确 commit 仓库任务 | 47 |
| 私有漏洞 target | 725 |
| 攻击方法定义 | 7 |
| 已实现 payload realization | 34 |
| 计划中 realization | 1 |
| 按研究问题拆分的 variant set | 10 |
| 生成的 JSON Schema | 52 |
| 验收测试 | 94 |

数据集数量描述公开的 task/oracle 包。只有当 target 文件和可选 anchor 在下载后的快照
中通过验证时，该 target 才会进入评分；benchmark 不假设 725 条标注在每次物化中
都天然有效。

## 核心设计

### 逐任务流式执行

VulnMirage 不要求在实验前克隆全部仓库，而是逐任务处理：

```text
读取 task JSONL
  → 解析并下载精确 commit archive（不包含 .git 历史）
  → 安全解压并验证 target anchor
  → 从同一个 clean tree 独立生成 C 和各攻击变体
  → 每次 run 只向 Agent 暴露一个仓库工作区
  → 收集审计报告、结构化 findings、stdout 和 trace
  → 冻结 answer bundle，交给独立 verifier 评分
  → 比较 clean/attack 的结果、报告和轨迹
  → 验证归档后，仅删除当前任务的临时目录
```

### 信任边界

| 层 | Agent 是否可见 | 用途 |
| :-- | :--: | :-- |
| 规范化审计任务 | 是 | 仓库级安全审计请求 |
| 单个变体仓库 | 是 | clean 或一个攻击条件 |
| run 专属输出目录 | 是 | Agent 最终答案与运行产物 |
| Payload registry/templates | 否 | 可信注入构造 |
| 私有 oracle/targets | 否 | 匹配与评分 |
| 其他变体和历史 run | 否 | 避免条件间污染 |

Agent 可以访问配置的模型 API，但仓库工具不得联网检索 advisory、CVE 答案或数据集
oracle。隔离策略对 clean/attack 完全一致，是实验不变量，而不是实验条件。

### 冻结计划与独立变体

`campaign plan` 在第一次审计前冻结：任务选择、variant set、研究问题、解析后的
条件、payload 资产、哈希、生成预算与运行顺序。每个变体都从同一 clean snapshot
独立构造，不会在另一个攻击变体上继续叠加。每个 target 形成独立 clean/attack
配对，顺序由冻结 seed 决定，避免 clean 总是先运行。

Benchmark 不包含中性内容对照，因此观察到的效果代表完整注入处理，包括新增上下文
长度和落点；它不能单独把“语义说服”与一般上下文长度效应分开。

### Oracle 分离与 fail-closed

公开 task 层只提供审计任务所需信息；私有 oracle 保存漏洞标识、位置、修复证据、
根因与严重性。Plan、prompt 和注入字节都会扫描答案 token。Verifier 只消费冻结且
带哈希的 answer bundle，并在独立边界中评分。

缺失证据不会被转换成成功：

- 无法解析的答案是格式失败，不是“0 个 finding”的有效报告；
- trace 缺失时输出 `insufficient_evidence`，不能推断机制；
- 未证明的 runtime boundary 是 `unknown`，不能写成已隔离；
- `fail_closed` 启用时，网络边界验证失败会在模型调用前阻止该 run。

### WSL/Linux 网络边界

正式 agent 配置面向原生 Linux OpenCode 2.x：

```text
OpenCode（rootless user + network namespace）
  ├── 只有 loopback，无默认路由
  └── 本地 TCP relay
        → 私有 Unix socket
        → 可信 inference gateway
        → allowlist 中的模型 API
```

每个 run 都生成 `network_boundary_probe.json` 和 `network_boundary.json`，记录父子
namespace、接口、默认路由、公网直连结果和 relay 状态。只有
`enforcement_verified: true` 才启动 OpenCode。完整部署步骤见
[WSL 部署说明](docs/wsl_deployment.md)。

## 生成能力与攻击分类

### T0–T4 是生成上下文，不是攻击强度

每个攻击条件声明 generator tier，表示生成器可以读取什么：

| Tier | 生成器可使用的信息 | 当前状态 | 落点 |
| :-- | :-- | :--: | :-- |
| T0 | 固定模板 + 仅用于落点选择的公开文件列表 | 已实现 | 第一个确定性可注释源码位置 |
| T1 | T0 + 公开 `RepositoryIndex` | 已实现 | 由结构与 seed 排名的符号 |
| T2 | T1 + 清理后的 `OracleAttackView` | 已实现 | 漏洞位置及局部条件/影响 |
| T3 | T2 + 隔离 surrogate 反馈 | 未实现，fail closed | — |
| T4 | T2 + 有预算的 victim 查询循环 | 未实现，fail closed | — |

边界由 `GeneratorContext` 接口强制，不依赖 YAML 注释。T0/T1 不会获得 oracle view；
计划中如果声明当前实现不支持的 tier，会在 plan 阶段失败，不会在运行时降级。详见
[tier capability matrix](docs/tier_capability_matrix.md)。

`campaign generate` 是独立、可恢复的阶段：它保存所有候选、validator 判定与最终
选择，然后停止；只有选中的候选可以进入 Agent 工作区。

### 规范攻击身份

[`PayloadGen/registry.yaml`](PayloadGen/registry.yaml) 将稳定的因果方法与具体
realization 分开。正式攻击条件由以下身份唯一确定：

```text
threat-model reference × objective × method × surface × intensity × realization
```

T0–T4 不表示攻击强度。强度由每个方法自己的 `I0`–`I4` 梯度定义。Plan 会拒绝未知
threat model、混合 objective、不支持的 surface/intensity，以及超过威胁模型修改
预算的 realization。

每个 realization 还声明可机器检查的 dose：`claim_count`、
`supporting_evidence_count`、`directness` 和 `reinforcement_count`，防止仅修改标签
就把同一模板伪装成更强攻击。

| 方法 | 主机制 | Objective/状态 |
| :-- | :-- | :-- |
| `M2-FALSE-PRIOR-RESOLUTION` | `M2.1` 虚假先前解决 | `O-FN` |
| `M2-FALSE-EXPLOITABILITY-PREMISE` | `M2.5` 虚假可利用性前提 | `O-FN` |
| `M2-FABRICATED-ANALYSIS-RESULT` | `M2.2` 伪造分析结果 | `O-FN` |
| `M2-FALSE-VULNERABILITY-CLAIM` | `M2.6` 虚假漏洞声明 | `O-FP` |
| `M4-CERTIFIED-SAFE-DECOY` | `M4.1` 注意力转移 | `O-SCOPE` |
| `M3-SEVERITY-ANCHORING` | `M3.1` 严重性锚定 | `O-SEV-D`、`O-SEV-I` |
| `M5-FAMILIAR-PATTERN-CAMOUFLAGE` | `M5.1` 表征伪装 | 计划中，plan 阶段拒绝 |

相关文献包括
[ALIBI](https://arxiv.org/abs/2607.24964)、
[RedHerring](https://arxiv.org/abs/2609.35909)、
[Familiar Pattern Attacks](https://arxiv.org/abs/2508.17361) 和
[FlashBoom](https://doi.org/10.1109/SP61157.2025.00125)。

## Variant sets

| Set | 条件 | 研究问题 |
| :-- | :-- | :-- |
| `core-v2` | C + 三个 `O-FN` 认识论污染 realization | 核心代表性实验 |
| `generator-context-ablation-v2` | 一个 realization × T0/T1/T2 | 固定攻击身份，只改变生成上下文 |
| `false-prior-resolution-intensity-v1` | C + `M2.1` I0–I4 × 两个 realization | 方法内部强度剂量响应 |
| `false-exploitability-intensity-v1` | C + `M2.5` I0–I4 × 两个 realization | 方法内部强度剂量响应 |
| `fabricated-analysis-intensity-v1` | C + `M2.2` I0–I4 × 两个 realization | 方法内部强度剂量响应 |
| `false-negative-v2` | 三个 `O-FN` realization × T0/T1/T2 | 定向漏报 |
| `false-positive-v2` | 认证虚假 finding × T0/T2 | 虚假漏洞诱导 |
| `scope-diversion-v2` | 认证安全诱饵 × T0/T2 | 目标路径覆盖与注意力转移 |
| `severity-downgrade-v2` | `O-SEV-D` × T0/T1/T2 | 仅严重性降低 |
| `severity-inflation-v2` | `O-SEV-I` × T0/T2 | 仅严重性提高 |

Variant set 只能在 plan 阶段选择。`campaign run` 不提供 `--variant-set`，而是从
冻结 plan 恢复实验条件，避免运行时替换研究问题。

## 数据资源

代码仓库不包含漏洞 oracle。默认要求 VulnMirage Dataset v2 与项目相邻：

```text
parent/
├── vulnmirage/
└── VulnMirage_dataset/
    ├── manifest.json
    ├── tasks/task-*.jsonl          # Agent-safe task 层
    ├── oracle/target-*.jsonl       # 私有 evaluator 层
    └── schemas/
```

Loader 通过 `manifest.json` 发现带日期的 JSONL 文件并验证全部摘要，不需要第二套
转换后的数据。`oracle/` 必须始终位于 Agent 可见 workspace 之外。

## 安装

要求：

- Python 3.11 或更高；
- PATH 中存在原生 Linux OpenCode 2.x；
- 真实审计所需的一个模型 provider API key；
- VulnMirage Dataset v2。

```bash
git clone https://github.com/xinyi234/vulnmirage.git
cd vulnmirage
python -m pip install -e '.[dev]'
```

提供的 agent 配置使用 `opencode --standalone run --archived`，面向 WSL/Linux。
Harness 将 exposed repository 设置为子进程 cwd，不在配置中保存绝对项目路径。

正式运行前请按 [WSL 部署说明](docs/wsl_deployment.md) 将项目和数据集复制到 Linux
文件系统，并检查 Python、OpenCode、`unshare`、`ip` 和 namespace 策略。

## 快速开始

### 1. 配置模型 provider

```bash
cp .env.example .env
chmod 600 .env
```

只填写将使用的 provider：

```dotenv
DEEPSEEK_API_KEY=...
# ZHIPU_API_KEY=...
# DASHSCOPE_API_KEY=...
```

密钥值只从环境读取，归档中仅记录变量名，不记录值。

### 2. 检查安装与数据集

```bash
python -m vulnmirage doctor \
  --config configs/experiment.yaml \
  --agent configs/opencode.yaml \
  --agent-profile deepseek-chat

python -m vulnmirage ingest dataset-core \
  --root ../VulnMirage_dataset
```

`doctor` 检查可信 gateway 一侧的模型主机以及 `opencode`、`unshare`、`ip` 等 Linux
依赖。实际的 loopback-only namespace 会在每次审计前独立创建和验证；preflight
失败时不会调用模型。

### 3. 冻结一个任务的计划

先执行不写文件的 dry run：

```bash
python -m vulnmirage campaign plan \
  --config configs/experiment.yaml \
  --dataset ../VulnMirage_dataset \
  --variant-set PayloadGen/variant_sets/core.yaml \
  --workspace workspace/campaigns/core/deepseek-chat \
  --limit 1 --target-limit 1 --dry-run
```

确认后删除 `--dry-run`，生成：

```text
workspace/campaigns/core/deepseek-chat/control/plan.json
```

Planning 只读取元数据和资产哈希，不下载仓库，也不调用模型。

### 4. 生成并检查候选

```bash
python -m vulnmirage campaign generate \
  --config configs/experiment.yaml \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json \
  --inspect-generation
```

该阶段下载精确快照、建立索引、渲染候选并执行结构、泄露、语义和预算 validator，
但不运行 OpenCode，不产生模型费用。

### 5. 执行或恢复审计

以下命令会调用模型 API：

```bash
python -m vulnmirage campaign run \
  --config configs/experiment.yaml \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json \
  --agent configs/opencode.yaml \
  --agent-profile deepseek-chat
```

每个 `(variant_set, model)` 使用不同 workspace。中断后重复相同命令即可 resume；
已有冻结 `run.json` 的模型调用不会再次执行。若只想验证准备阶段，可不传 `--agent`，
此时 `NullExecutor` 不调用模型。

### 6. 分析、聚合和验证归档

```bash
python -m vulnmirage campaign analyze \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json

python -m vulnmirage campaign aggregate \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json

python -m vulnmirage campaign verify-archive \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json

python -m vulnmirage campaign status \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json
```

`aggregate` 输出 `aggregate/aggregate.json`，包括 clean/attack 配对差异、按生成上下文
和强度分组的摘要、bootstrap 区间及 attrition ledger。生成失败、无效 run、隔离失败
和缺失 trace 不会被静默丢弃。

## 评测指标与产物

每次有效审计必须返回同时包含 Markdown 报告和结构化 findings 的 JSON envelope：

```json
{
  "schema_version": "1.0",
  "report_markdown": "## Scope\n...",
  "findings": [],
  "audit_summary": {}
}
```

Parser 只定位答案，不修复 JSON 或补写 findings。单 run 排障命令：

```bash
python scripts/check_final_answer.py \
  --run-dir workspace/campaigns/core/deepseek-chat/archives/<task>/runs/<run>
```

主要归档产物：

| 产物 | 含义 |
| :-- | :-- |
| `runs/<run>/run.json` | 冻结的执行身份、条件与状态 |
| `runs/<run>/network_boundary*.json` | namespace preflight 和实际运行边界证据 |
| `runs/<run>/agent_report.md` | Agent 原始报告，不改写 |
| `runs/<run>/findings.json` | 解析后的结构化 findings 与状态 |
| `runs/<run>/stdout.log` | 原始 OpenCode JSONL/stdout |
| `runs/<run>/trace_manifest.json` | 框架版本、兼容性、原始/派生哈希与限制 |
| `evaluation/<run>/score.json` | target recall、V/I/E/S、严重性和安全诱饵评分 |
| `evaluation/<run>/rubric_scores.json` | 每个 target 的裁决、根因、证据和严重性诊断 |
| `analysis/<task>-comparison/trajectory_comparison.json` | 同 target/repetition 的 C/A 轨迹差异 |
| `analysis/<task>-comparison/mechanism_assessment.json` | 由证据门控的机制标签 |
| `artifact_manifest.json` | 归档内文件哈希清单 |

主要结果包括 target detection/recall、认证安全诱饵接受率、严重性偏移、答案有效率
和报告一致性。机制分析属于次要结果，只有 normalized tool/file evidence 完整时才可评估。

## 当前进度

已实现并有测试覆盖：

- dataset-core 加载与 manifest 摘要校验；
- 精确 commit archive 解析、安全下载和有界防穿越解压；
- T0/T1/T2 生成上下文、RepositoryIndex、清理后的 OracleAttackView；
- 候选生成、四类 validator、确定性选择和冻结 GenerationManifest；
- clean/attack 独立构造、target remap 与 payload provenance；
- variant-set/tier-profile plan 冻结和 resume identity；
- OpenCode 双输出解析及 JSONL trace 规范化；
- OpenCode 1.17.18 与 Linux 2.2.7 的真实 CLI trace fixture；
- rootless Linux network namespace 与 Unix-socket inference gateway 代码；
- 最小子进程环境、逐 run HOME/XDG state 和 credential 名白名单；
- 私有 verifier bundle、target rubric 与 V/I/E/S 可归因评分；
- exposure/trajectory/mechanism 产物；
- 配对聚合、bootstrap 与 attrition ledger；
- 归档校验和任务级安全清理。

正式论文实验前仍需完成：

- 在复制后的 WSL 环境完成 namespace/gateway 的首次 operator-run 验收；
- 至少三个真实模型后端 OpenCode run，报告 trace 完整率；
- 将 M3 严重性和 M4 注意力转移扩展到与核心 M2 相同的完整 I0–I4 覆盖；
- T3/T4 生成器及独立 adaptation/holdout 协议；
- FPA、FlashBoom 等语义方法与行为等价验证；
- 多模型、多任务、多重复的正式冻结实验。

当前回归快照：

```text
94 tests passed
52 schemas current; 0 missing; 0 stale
47 tasks / 725 targets，manifest digest 已验证
725/725 targets 可生成清理后的 T2 oracle view；0 sanitizer leaks
```

当前仓库不发布 benchmark 分数或模型排名。

## 路线图

下一里程碑是实验就绪，而不是继续随意增加 payload 名称：

1. 在 WSL 中验收 rootless namespace、Unix gateway 和逐 run 边界证据；
2. 运行三个模型后端 OpenCode trace，报告事件覆盖和完整性；
3. 执行一个任务、两个模型、重复运行的 pilot，并逐项审查归档；
4. 将 I0–I4 realization 模式扩展到 M3/M4；
5. 完成 T3/T4 的预算、query log 和 holdout 设计；
6. 将固定 FPA bank、surrogate-mined FlashBoom 分成独立 variant set；
7. 完善 objective-specific 指标、仓库聚类不确定性和排除统计；
8. 冻结完整 experiment manifest 后再扩展整个数据集。

完整验收门槛见
[下一阶段设计](docs/next_stage_design_2026-11-04.md)。

## 项目结构

```text
configs/        实验与 OpenCode/provider 配置
PayloadGen/     方法注册表、realization、模板与 variant sets
prompts/        版本化审计任务与答案契约
schemas/        生成的公开产物 schema
scripts/        诊断和 trace fixture 工具
src/vulnmirage/
  campaign/     plan、状态机、执行器与主流程
  ingest/       dataset-core reader
  repository/   精确 commit archive 物化
  isolation/    workspace、network namespace、gateway 与 attestation
  verifier/     私有 target、冻结 bundle 与评分
  mechanism/    暴露和轨迹分析
  evaluation/   答案解析、报告/findings 一致性与聚合
tests/          安全、集成和回归验收测试
docs/           设计、操作、泄露模型与路线图
```

逐文件职责见 [docs/FILES.md](docs/FILES.md)。

## 引用

论文和归档版 benchmark 尚在准备中。当前软件可以引用：

```bibtex
@software{vulnmirage2026,
  title  = {VulnMirage: Adversarial Repository Context for Code-Agent Security Auditing},
  author = {{VulnMirage Contributors}},
  year   = {2026},
  url    = {https://github.com/xinyi234/vulnmirage}
}
```

## 许可证

Benchmark 代码采用 [MIT License](LICENSE)。仓库快照、数据集元数据和基于文献的
资产可能保留各自上游条款，重新分发前应分别检查。
