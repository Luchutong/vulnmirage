# VulnMirage 文件清单

只列当前仓库里存在的文件。旧的 release-bundle 流程（`generation/`、`manipulations/`、
`validation/`、`export/`、`evaluation/` 的统计部分、`payloads/`、git 物化、`store.py` 等）
已在 2026-11-04 的改造中整体删除，备份在 `LAB/_archive/vulnmirage_legacy_20261104-1051`。

文件数量会随生成 schema 与 PayloadGen 方法扩展；以本清单的职责边界为准，不把数量当作接口。

---

## 1. 仓库根目录

| 文件 | 作用 |
| --- | --- |
| `README.md` | 总览：一次实验的链路、快速开始、被验证而非被声明的性质、已知局限。 |
| `pyproject.toml` | 打包与工具配置：运行依赖（pydantic / PyYAML）、`vulnmirage` 命令入口、pytest（`integration` / `security` marker）、ruff、mypy。 |
| `.env` | 本机凭据（真实 key），已 gitignore，不属仓库内容。 |
| `.env.example` | 需要的环境变量名：`DEEPSEEK_API_KEY`、`ZHIPU_API_KEY`、`DASHSCOPE_API_KEY`（由 agent 配置的 `requires_env` 声明）。 |
| `.gitignore` | 忽略 `workspace/`、`.env`、缓存与构建产物。 |
| `LICENSE` | MIT。 |

---

## 2. `configs/`

| 文件 | 作用 |
| --- | --- |
| `experiment.yaml` | **唯一实验配置**：`archive`、`isolation`、`verifier`、`output_contract`、`campaign`（含生成器上下文档案与 `payload_catalog: PayloadGen/registry.yaml`）；默认引用 `PayloadGen/variant_sets/core.yaml`，也可在 plan 时通过 `--variant-set` 覆盖。 |
| `opencode.yaml` | **唯一的 agent 配置**：面向 WSL/Linux OpenCode 2.x，使用 `opencode --standalone run --archived`；顶层共享 `mode`、答案/trace adapter、版本命令、argv 和环境白名单，`profiles:` 分别声明 DeepSeek/GLM/Qwen。Harness 以暴露仓库为 cwd，不在配置中保存绝对路径。 |
| `opencode.json` | OpenCode 自身的 provider/model 配置，被 `opencode.yaml` 的 profile 通过 `--model`/provider 引用。 |

---

## 3. `prompts/`

| 文件 | 作用 |
| --- | --- |
| `audit_task.md` | 审计请求 + **唯一的输出契约**（`schema_version` / `report_markdown` / `findings` / `audit_summary`）。`## OUTPUT CONTRACT` 段会被 `campaign/task_prompt.py` 拼到规范化后的数据集 prompt 后面，因此该段是逐字相同的基准常量。 |

---

## 3.1 `PayloadGen/`

| 文件 | 作用 |
| --- | --- |
| `README.md` | 方法库边界、状态语义、模板变量与私有安全诱饵规则。 |
| `registry.yaml` | schema 3 规范注册表：稳定 Method、单一 primary Mechanism、支持的 Objective/Surface、方法特定 I0–I4 强度档案，以及具体 Realization。 |
| `threat_models/repository_content.yaml` | 独立威胁模型：攻击者控制面、oracle/feedback 权限、变更预算及禁止能力；攻击分类只引用其 ID。 |
| `methods/A2/templates/*`、`methods/A3/...`、`methods/S1/...`、`methods/S2/...` | 按 tier 分层的模板：`t1_repository.txt` 使用公开仓库语境，`t2_oracle.txt` 使用清理后的 `{precondition}` / `{boundary_claim}` / `{dangerous_effect}`。 |
| `realizations/M2-*/i0..i4/*` | `M2.1`、`M2.2`、`M2.5` 三个核心 O-FN 方法的完整强度梯度；每级两个独立措辞 realization。 |
| `variant_sets/core.yaml` | 单一 `O-FN` 核心集合：C + 三个认识论污染 realization。 |
| `variant_sets/generator_context_ablation.yaml` | 生成上下文消融：固定 Objective/Method/Surface/Intensity/Realization，只改变 T0/T1/T2 provenance。 |
| `variant_sets/intensity_false_exploitability.yaml` | 强度消融：固定 T2、Threat Model、Objective、Method 和 Surface，只改变 I0–I4；每级两个 realization。 |
| `variant_sets/intensity_false_prior_resolution.yaml`、`intensity_fabricated_analysis.yaml` | 分别对 `M2.1` 和 `M2.2` 执行相同的固定 T2、双 realization 强度消融。 |
| `variant_sets/false_negative.yaml` | `O-FN` 漏报实验。 |
| `variant_sets/safe_decoy.yaml` | `O-FP` 认证虚假 finding 实验。 |
| `variant_sets/scope_diversion.yaml` | `O-SCOPE` 认证安全诱饵的注意力转移实验。 |
| `variant_sets/severity.yaml`、`severity_inflation.yaml` | 分开的 `O-SEV-D` 与 `O-SEV-I` 实验。 |
| `templates/*` | 确定性载荷模板（T0 基线）；模板及渲染结果哈希进入 plan/patch 产物。 |

---

## 4. `schemas/`（52 个，全部生成物）

`vulnmirage schemas` 从 pydantic 模型生成，勿手改；`schema_index()` 会报告 `missing` / `stale`。

**答案契约（4）**

| 文件 | 源模型 | 作用 |
| --- | --- | --- |
| `audit_output.schema.json` | `AuditReportEnvelope` | 双输出信封：`report_markdown` + `findings` + `audit_summary`。 |
| `finding.schema.json` | `FindingEnvelope` | 旧的只有 findings 的信封（兼容历史答案）。 |
| `agent_finding.schema.json` | `AgentFinding` | 单条 finding 的字段契约。 |
| `code_location.schema.json` | `CodeLocation` | `file` + 行号 + 可选代码片段。 |

**campaign 契约（12）**：`campaign_plan`（`control/plan.json`）、`campaign_plan_task`、
`campaign_plan_variant`、`campaign_variant_set`（研究问题与条件集合）、`campaign_state`（阶段状态机）、`campaign_source_manifest`（归档与树身份）、
`campaign_task_manifest`（源/有效 prompt 哈希与变换记录）、`campaign_variant`（单变体构建结果）、
`campaign_variants_frozen`（冻结集合）、`campaign_run_record`（每 run 记录）、
`campaign_artifact_entry`（归档清单条目）。

**隔离与泄露（3）**：`isolation_attestation`（9 项不变量的证据）、`isolation_egress_probe`（出口探测结果）、
`leakage_controls`（渠道 → controlled/failed/unknown）。

**生成与攻击身份契约（17）**：`condition_spec`、`experiment_cell`、
`campaign_plan_generation`（seed 与各 tier 档案）、`repository_index`（公开仓库索引）、
`oracle_attack_view`（清理后的 T2 局部视图）、`candidate_payload`（候选载荷 + 落点 + provenance）、
`candidate_validation`（四个验证器的 pass/fail/unknown/not_applicable）、
`generation_manifest`（输入哈希 + 候选 + 验证 + 选择）、`target_remap`（编辑后的目标重映射）、
`adaptation_query`（T3/T4 查询记录，当前无生成器）、`aggregate_result`（配对聚合 + 流失账）、
`paired_comparison`（单任务 clean↔attacked 差值），以及 `payload_catalog`、
`payload_attack_method`、`payload_realization`、`payload_realization_dose`、`payload_threat_model`、
`attack_condition_identity`（Threat Model 引用 × Objective × Method × Surface × Intensity × Realization）。

**评估（7）**：`verifier_bundle`（冻结输入包）、`verifier_targets`（私有目标视图）、
`verifier_target_rubric`（单目标私有 V/I/E/S 判据）、`verifier_rubric_scores`（逐目标诊断结果）、
`verifier_score`（单次评分摘要）、`verifier_attestation`（评估器自证）、
`verifier_untrusted_input`（报告文本处置记录）。

**答案质量（1）**：`output_consistency`（报告 ↔ findings 的 id 覆盖与冲突）。

**机制（3）**：`exposure_report`（载荷是否真的到过模型）、`trajectory_comparison`（C/A 轨迹对比）、
`mechanism_assessment`（机制标签 + 证据 + 替代解释）。

**轨迹（5）**：`trace_event`（框架无关事件）、`trace_tool_call`（工具状态）、
`trace_file_access`（文件证据）、`trace_manifest`（原始输入与派生产物哈希）、
`trace_completeness`（完整 / 部分 / 缺失及原因）。

---

## 5. `scripts/`

| 文件 | 作用 |
| --- | --- |
| `check_final_answer.py` | 一次 run 的排障：`--run-dir` 检查整套产物、`--raw` 检查答案文件、`--stdout` 从事件流抽答案再检查、`--demo` 自测抽取器。不跑模型、不写 workspace。 |
| `capture_opencode_trace_fixture.py` | 运行真实 OpenCode CLI，但把推理端替换为 localhost 确定性 SSE stub；生成脱敏、版本化的 JSONL 回归夹具，不调用外部模型。 |

---

## 6. `docs/`

| 文件 | 作用 |
| --- | --- |
| `benchmark_revision_plan_2026-11-03.md` | 改造方案原文（13 节）：研究目标、输入、归档物化、变体、隔离、双输出、机制分析、评分、调度、布局、模块、入口与验收。 |
| `benchmark_revision_2026-11-03_status.md` | 方案 ↔ 实现 ↔ 测试对照，含已删除的旧模块与仍然存在的局限。 |
| `next_stage_design_2026-11-04.md` | 下一阶段设计：当前设计与进度、真实 OpenCode trace、强制网络边界、AST payload generator、FPA/FlashBoom/RedHerring、实验矩阵、聚合统计和 G0–G5 验收门槛。 |
| `adaptive_attack_benchmark_architecture_2026-11-04.md` | 待审核的自适应攻击架构：T0–T4 威胁层级、双阶段冻结、PayloadGen v2、oracle 最小视图、生成/验证/选择、运行隔离、T3/T4 协议、归档、里程碑与验收门槛。 |
| `tier_capability_matrix.md` | tier 的可读边界：每个 tier 能读什么、两条强制点、T2 允许/禁止字段、T0 落点的诚实标注、725/725 真实 target 的清理结果、T3/T4 缺席原因。 |
| `campaign.md` | 流程手册：阶段图、命令、目录布局、两种执行器、不变量表、失败语义。 |
| `wsl_deployment.md` | WSL/Linux 部署手册：复制到 Linux 文件系统、原生 OpenCode/Python、rootless namespace、API key、单仓库 plan/generate/run、边界证据与故障排查。 |
| `leakage_channels.md` | 泄露渠道控制矩阵：9 条渠道的原因、控制、检查、残余风险，以及“哪些只能是 unknown”。 |
| `FILES.md` | 本文件。 |

---

## 7. `tests/`

| 文件 | 作用 |
| --- | --- |
| `test_campaign_revision.py` | 验收覆盖数据集加载与摘要校验、prompt 规范化（剥身份 / 保网络声明 / 整段删载体提醒 / 幂等）、归档下载与恶意归档拒绝（穿越 / 绝对路径 / 符号链接 / 预算）、嵌套历史拒绝、变体独立构建与空操作拒绝、隔离证据（无 `.git`、无 oracle、无同级 run、脏 state、可达答案主机五种失败）、评估器（评分、拒绝带 oracle 的包、拒绝被篡改的包、无执行 sink、报告注入）、输出一致性、机制分析（缺证据 → insufficient_evidence）、端到端 C/A1、不合格 run 不进分母、resume 拒绝改过的 plan、清理范围、产物写入器，以及单文件多 profile 的 agent 配置解析。 |
| `test_tier_generation.py` | 生成上下文验收：全部已实现 realization × T0/T1/T2 均能生成可选候选，T0 与旧渲染逐字节一致、oracle 视图清理、答案 token 拦截、结构/预算验证、确定性选择、目标重映射、预运行冻结、plan `--dry-run`，以及 52 个 schema 无 missing/stale。 |
| `test_target_rubric.py` | 私有 target rubric 验收：V/I/E/S 全通过、只有位置或 CWE 不算根因识别、没有结构化仓库证据不算可归因，以及旧 target set 缺少 rubric 时只能记 `not_available`。 |
| `test_attack_taxonomy.py` | 分类契约验收：Method/Realization 分离、I0–I4 完整、强度 dose 不可伪标、三个核心 M2 方法每级两个 realization、威胁模型独立、generator tier 不冒充强度、混合 Objective 和未知威胁模型在生成前被拒绝。 |

---

## 8. `src/vulnmirage/` 顶层模块

| 文件 | 作用 |
| --- | --- |
| `__init__.py` | 包元数据与 `SCHEMA_VERSION`；说明构造 / 运行 / 评估三段职责。 |
| `__main__.py` | `python -m vulnmirage` → `cli.main()`。 |
| `cli.py` | 命令入口：`doctor`、`schemas`、`ingest dataset-core`、`campaign {plan,generate,run,resume,analyze,aggregate,verify-archive,status}`。`plan --dry-run` 只解析不写；`generate --inspect-generation` 打印候选/验证/选择；`run` 支持 `--agent-profile`。全部输出 JSON，失败返回非 0。 |
| `config.py` | 全部配置模型（严格、禁未知键、禁密钥）+ 加载器；`AgentConfig` 描述 argv/占位符/凭据名/答案抽取/trace adapter；`AgentProfileConfig` 支撑单文件的 `profiles:` 多模型配置，`load_agent_config(path, profile=…)` 解析 `{model}` 并把 profile 名并入返回摘要。`TierProfileConfig` / `GenerationBudgetConfig` 冻结生成预算。 |
| `tiers.py` | **tier 唯一定义**：`TIERS` / `TIER_INDEX` / `INDEXED_TIERS` / `ORACLE_VIEW_TIERS` / `is_implemented()`。config、payloadgen、pipeline 共用一处定义，避免“声明 T2、实跑 T0”。 |
| `payloadgen/` | 生成子系统包（见 §8.1）；旧的单文件 `payloadgen.py` 已拆成包，包的 `__init__` 保持同名导出。 |
| `diagnostics.py` | `doctor`：配置与模板契约、数据集摘要、归档可用性与写权限、**实际 egress 探测**、agent 可执行文件与凭据名。不下载、不调模型。 |
| `paths.py` | 路径规范化与越界检查：`safe_join` / `ensure_within` / `normalize_relpath` / `project_root`。 |
| `hashing.py` | 确定性哈希、ID、种子与原子写。 |
| `errors.py` | 带稳定 `error_code` 的异常族（含 `IsolationError` / `VerifierError` / `CampaignError`）。 |
| `logging.py` | 结构化 JSON 日志 + 密钥脱敏。 |
| `env.py` | 零依赖 `.env` 读取（不覆盖已有环境变量）。 |
| `normalization.py` | CWE 列表与严重性等级归一化（解析与评分共用）。 |
| `schemas.py` | 从模型生成/校验全部 JSON Schema（`SCHEMA_FILES` + `benchmark_schema_files()`）。 |
| `py.typed` | PEP 561 类型标记（空文件）。 |

---

## 8.1 `payloadgen/`（生成子系统，15 模块）

| 文件 | 作用 |
| --- | --- |
| `__init__.py` | 公开门面：注册表、引擎、索引、oracle 视图、重映射、契约与旧渲染入口。 |
| `taxonomy.py` | 规范攻击身份：Objective、单一主 Mechanism、Artifact+Zone Surface、方法特定 I0–I4 Intensity、独立 ThreatModel 引用。 |
| `contracts.py` | `ConditionSpec` / `ExperimentCell` / `CandidatePayload` / `ValidatorResult` / `CandidateValidation` / `SelectionRecord` / `GenerationManifest` / `AdaptationQuery`；required 验证不过的候选不可选（`unknown` 不是 `pass`）。 |
| `catalog.py` | schema 3 Method/Realization 注册表与威胁模型装载；在生成前验证 Objective、Surface、Intensity、威胁模型、变更预算及 generator backend 一致性。 |
| `render.py` | 确定性模板渲染、注释前缀、模板路径解析、受限 Python AST 的**无执行子集**证书。 |
| `legacy.py` | 包的兼容薄层：`realize_payload` 保持逐字节一致的旧渲染（T0 golden 用它对照）；`expected_severity` 不再取自 oracle。 |
| `repository_index.py` | `RepositoryIndex`：文件语言/角色/摘要/行数、AST 或文本降级符号、注释风格、TODO 行数、sink 文件（不含 oracle 标签）；`digest()` 排除易变字段，同树同版本同摘要。 |
| `oracle_view.py` | `OracleAttackView` 白名单清理器：只留位置、`attacker_controlled_input`、preconditions、`dangerous_effect`、boundary claims；CVE/CWE/title/description/excerpt/fix 一律不复制；`assert_view_is_clean()` 用答案 token 复扫。 |
| `context.py` | `GeneratorContext`：tier 允许字段表 + `assert_matches_tier()`；T0 仅用公开索引确定静态落点，T0/T1 拿到 oracle 视图会直接报错。 |
| `generators/` | `static`（T0，固定文本 + 公开索引确定性落点）、`repository_adaptive`（T1，公开索引排序落点）、`oracle_guided`（T2，清理视图落点）、`model_guided`（T3/T4 抛 `unsupported_tier`）。 |
| `validators/` | `structural`（路径/预算/锚点唯一/受保护区）、`leakage`（答案 token + tier 字段越权）、`semantic`（插入行必须全是注释；`.py` 需可解析；安全诱饵需证书；无 profile 记 `unknown`）、`budget`。 |
| `selection.py` | 预声明打分 + `candidate_id` 确定性 tie-break；记录 policy/scores/ranked/eliminated，生成前算完。 |
| `remap.py` | 目标重映射：symbol 声明行求 delta（保持函数内偏移）→ anchor 窗口唯一命中 → line delta；不唯一即 `unique=False`，调用方拒绝该 variant。 |
| `engine.py` | 唯一入口 `generate_manifest()`：context→候选→验证→选择→manifest；`selected_candidate()` / `candidate_to_edit()` / `attach_remap()`。 |

---

## 9. `campaign/`（6 模块）

| 文件 | 作用 |
| --- | --- |
| `plan.py` | 离线冻结计划：读任务索引、规范化 prompt 取哈希、解析归档请求、校验变体声明，写 `control/plan.json`（**不含 target id / CVE / CWE**）；新增 `PlanGeneration`（seed + 各 tier 候选预算/选择策略/限额）与每个条件的 `condition_id` / `tier`；不实现的 tier 在 plan 阶段即失败。 |
| `task_prompt.py` | 把数据集 `task_prompt` 规范成 agent 实际看到的任务：7 条版本化规则（剥仓库名/commit/tag、改写网络声明、整段删载体提醒、删数据集 JSON 提示、删冻结文件数、补网络声明、清理排版）+ 答案 token 复扫；源与有效 prompt 都留哈希。 |
| `variants.py` | 从同一 clean 树**独立**构建 C/A：结构化编辑（create / append / insert_before），前置条件不满足即报错（绝不产生空操作变体），并拒绝含答案 token 的 payload；`AppliedEdit` 记录字符偏移与行号，供目标重映射使用；`VariantBuild` 记录 `tier` / `candidate_id` / `generation_manifest_sha256` / `remap_sha256`。 |
| `executor.py` | 一次审计怎么跑、答案怎么收集：`CommandExecutor`（命令自己写 `{output}`）、`StdoutExecutor`（捕获 stdout 并抽取最后一个 JSON 答案 / 事件流最后一段 text）、`NullExecutor`（只准备与取证）、`extract_final_answer()`。所有 executor 都以 exposed repo 为 cwd；路径占位符按框架需要选用。 |
| `state.py` | 每任务阶段机：`pending→downloading→extracted→prepared→indexed→generation_started→candidates_validated→variants_frozen→auditing→scoring→mechanism_analysis→archived→cleaned`，不可跳步或回退；记录历史与哈希；plan 或配置变了就拒绝 resume。 |
| `pipeline.py` | **主干**：下载归档 → 安全解压（+ 嵌套历史拒绝）→ 快照校验与私有目标视图 → **建索引** → **逐条件生成/验证/选择并冻结 manifest** → 按选中候选建树 + **目标重映射** → 逐变体逐重复审计（新 exposed 根 + egress 探测 + attestation + executor）→ 冻结 bundle 交独立评估器评分 → 机制分析 → 归档清单 → 校验后清理。另有 `generate_only()` / `inspect_generation()` / `aggregate()`。 |

---

## 10. `isolation/`（7 模块）

| 文件 | 作用 |
| --- | --- |
| `layout.py` | `ExposureLayout`：`tmp/<task>/{prep,exposed,state}` 与 `archives/`、`private/` 分离；每次 run 的 exposed 根只有 `repo/` + `out/`；提供 `reset_exposed()` / `cleanup()` / `assert_contained()`。 |
| `network.py` | 工具出口：`build_restricted_agent_environment()` 从空环境开始，只复制 agent 白名单和声明的模型凭据，再加离线提示；`probe_egress()` 真连推理网关与答案主机，并严格区分 `observed_unreachable` 与 executor 证明的 `enforced_blocked`。 |
| `gateway.py` | Linux namespace 的可信 inference relay：把 OpenCode provider URL 改写到 loopback，经私有 Unix socket 只转发到配置与 allowlist 同时允许的 HTTPS 模型主机。 |
| `namespace_child.py` | rootless namespace 子进程：启用 `lo`、TCP→Unix relay，证明 netns 不同、只有 loopback、无默认路由、公网直连失败，并在证明通过后才执行 OpenCode。 |
| `attestation.py` | **隔离证据**：9 项不变量（repo 可读、树等于冻结变体、无 `.git`、exposed 根无 oracle、无同级 run、私有区不在 exposed 内、state 为空、out 可写、egress 被封）+ 运行时边界；`unknown` 永不写成 `pass`；`condition_independent: true`。 |
| `channels.py` | **泄露渠道注册表**：9 条渠道 × 控制 × 检查 + 残余风险；`build_control_report()` 把 attestation 与阶段证据合成 `leakage_controls.json`，没跑过的检查记 `unknown`。 |

---

## 11. `verifier/`（7 模块）

| 文件 | 作用 |
| --- | --- |
| `bundle.py` | 冻结输入包：只允许 `final_raw.txt` / `events.normalized.jsonl` / `run.json` / `meta.json` / `isolation_attestation.json`（+ 可选 `file_access` / `tool_calls` / trace manifest/completeness），逐文件 sha256；拒绝被篡改的包、拒绝包内出现 oracle、拒绝包与 private 根相互嵌套。 |
| `untrusted.py` | 把提交当数据：限长、剥控制字符、去掉围栏自身 token 再包进 `<UNTRUSTED_…>`；`assert_no_execution_sinks()` 机械扫描自身源码确认没有 subprocess/eval/exec/pickle/yaml.load 出口。 |
| `targets.py` | 私有目标与 `SafeDecoy` 视图 + 匹配：**必须同文件**，行邻近与 CWE 重叠加权；普通未命中 finding 仍是 `unmatched`。 |
| `rubrics.py` | 从私有 oracle 构造逐目标 rubric，并确定性计算 V（裁决）、I（根因识别）、E（仓库证据）、S（严重性）与 A=V∧I∧E；缺失判据不推断为通过。 |
| `service.py` | 独立评估器：写 `rubric_scores.json` 和 `score.diagnosis`；同时匹配私有安全诱饵并写 `safe_decoy_matches.json` 与 `score.false_positive`。 |
| `__main__.py` | `python -m vulnmirage.verifier --private … --bundle … --out …`：独立进程入口。 |
| `__init__.py` | 子包导出。 |

---

## 12. `mechanism/`（2 模块）

| 文件 | 作用 |
| --- | --- |
| `analysis.py` | 只读归档产物的机制分析：`exposure.json`（payload 是否真的返回给模型，依据 tool-result 而非仅文件访问）、`trajectory_comparison.json`（C/A 的文件覆盖、工具调用、目标文件与反证文件触达）、`mechanism_assessment.json`（多标签 + 置信度 + 事件 id + 替代解释；证据不足即 `insufficient_evidence`）、`case_analysis.md`。 |

---

## 13. `trace/`（5 模块）

| 文件 | 作用 |
| --- | --- |
| `opencode.py` | 解析 OpenCode `--format json` JSONL；按稳定顺序输出事件/tool/file-access，路径限制为工作区相对形式，参数与输出机械脱敏。 |
| `normalize.py` | 将不可修改的 `stdout.log` 派生为三份 JSONL、`trace_manifest.json` 和 `trace_completeness.json`，绑定源/输出 SHA-256，并按已验证 OpenCode 版本标记兼容性。 |
| `models.py` | 五类 trace 的严格 pydantic 契约、适配器版本及真实 CLI 夹具已验证的框架版本。 |
| `completeness.py` | 依据终止事件、最终文本、tool terminal state、无效行和未知事件评估 complete/partial/missing；不补造事件。 |
| `__init__.py` | 子包导出。 |

---

## 14. `ingest/`（2 模块）

| 文件 | 作用 |
| --- | --- |
| `dataset_core.py` | **唯一数据集入口**：读 `manifest.json` + `tasks/task-*.jsonl` + `oracle/target-*.jsonl`，校验记录摘要；`eligibility_level()` 分 `rejected / snapshot_verified / annotation_verified`（不伪造 `executable_verified`）；导出日期后缀从 manifest 发现，不硬编码。 |
| `__init__.py` | 子包导出。 |

---

## 15. `repository/`（2 模块）

| 文件 | 作用 |
| --- | --- |
| `archive.py` | **唯一快照机制**：provider URL 解析（github / gitlab / local_zip / local_tree）、重定向白名单、TLS、字节预算、zip 校验、安全解压（拒穿越/绝对路径/符号链接/设备文件、大小写冲突、深度与体量预算、剥单顶层目录）、树摘要、嵌套历史检测、按 repo+commit 缓存。 |
| `__init__.py` | 子包导出。 |

---

## 16. `harness/`（3 模块）

| 文件 | 作用 |
| --- | --- |
| `sandbox.py` | 进程控制：独立 session、stdout/stderr 重定向到归档 run 目录、超时后杀掉整棵进程树（避免子进程占着工作区）。 |
| `artifacts.py` | 答案产物写入：`findings.json`（规范化 + 解析状态）、`agent_report.md`（agent 原文，不得改写）、`audit_report.md`（确定性 evaluator 视图）、`output_consistency.json`。解析失败按失败渲染，绝不写成“无发现”。 |
| `__init__.py` | 子包导出。 |

---

## 17. `evaluation/`（3 模块）

| 文件 | 作用 |
| --- | --- |
| `parser.py` | 答案解析：优先双输出契约，回退旧 findings-only 并标记；记录被忽略的顶层键；`output_consistency()` 对比报告与 findings 的 id 覆盖（consistent / divergent / report_missing / no_output）。 |
| `aggregate.py` | 读冻结归档做配对聚合：按 task 配对 clean↔attacked（repo 为聚类层级）、计算 recall 差与隐藏目标、按 tier 汇总、对配对差值做 percentile bootstrap，并输出流失账（生成失败、被验证拦下的候选、无效/不合格 run、缺 trace）。不重跑 agent。 |
| `__init__.py` | 子包导出。 |

---

## 18. `models/`（4 模块）

| 文件 | 作用 |
| --- | --- |
| `finding.py` | `AgentFinding` / `AuditSummary` / `FindingEnvelope`（旧）+ `AuditReportEnvelope`（双输出）/ `EvidenceCitation`。 |
| `repository.py` | `CodeLocation`（file + 行号 + 可选片段与哈希）/ `RepositoryRef`。 |
| `enums.py` | `SeverityLevel` 与 `SEVERITY_ORDINAL` 等共享枚举。 |
| `__init__.py` | 公开导出表（只导出 campaign 还需要的契约）。 |

---

## 19. 不参与运行但应保留的文件

- `.env` 是本机凭据文件，已 gitignore，不属于可发布实验资产。
- `docs/*.md`、根 `README.md` 和 `PayloadGen/README.md` 不在运行 import
  闭包中，但记录设计决策、操作协议、已知限制和方法来源，属于复现材料。
- `tests/test_campaign_revision.py` 不参与正式 run，用于阻止隔离、oracle 泄露、
  变体构建和评分语义回归。
- `tests/fixtures/opencode/<version>/` 不参与正式 run；它是由真实 OpenCode CLI
  产生、脱敏后冻结的适配器兼容性证据。

当前没有仅为旧流程保留的 `src` 模块；75 个 Python 模块都挂在
`campaign` / `verifier` / `payloadgen` 入口的 import 闭包上。

---

## 20. 调用主链

```text
cli campaign plan
  └ ingest.dataset_core.load_dataset_core
      └ campaign.plan.build_plan                      → control/plan.json
          ├ campaign.task_prompt.build_effective_task  (prompts/audit_task.md 的契约段)
          └ campaign.plan.plan_generation              (seed + tier 档案)

cli campaign generate
  └ campaign.pipeline.CampaignRunner.generate_only
      ├ repository.archive.{resolve_archive_request,download_archive,safe_extract}
      ├ payloadgen.repository_index.build_repository_index
      ├ payloadgen.oracle_view.build_oracle_attack_view     (仅 T2+)
      └ payloadgen.engine.generate_manifest
            └ validators.{structural,leakage,semantic,budget} → selection.select
                                                        → generation/manifests/*.json

cli campaign run
  └ campaign.pipeline.CampaignRunner.run_task
      ├ repository.archive.{resolve_archive_request,download_archive,safe_extract}
      ├ payloadgen.engine.{selected_candidate,candidate_to_edit} → campaign.variants.build_variant
      ├ payloadgen.remap.remap_targets                      → private/target_remap/*.json
      ├ isolation.layout + isolation.network.probe_egress + isolation.attestation.run_attestation
      ├ campaign.executor.{CommandExecutor|StdoutExecutor|NullExecutor}
      │    └ harness.sandbox.run_agent_process
      ├ trace.normalize.normalize_trace → trace/{events,tool_calls,file_access,manifest,completeness}
      ├ evaluation.parser.parse_agent_output + harness.artifacts.write_findings_and_report
      ├ verifier.bundle.freeze_bundle → verifier.service.evaluate_bundle
      │    （或另进程：python -m vulnmirage.verifier）
      ├ mechanism.analysis.{analyze_exposure,compare_trajectories,assess_mechanisms,write_analysis}
      └ isolation.channels.build_control_report → artifact_manifest.json → cleanup_manifest.json
```
