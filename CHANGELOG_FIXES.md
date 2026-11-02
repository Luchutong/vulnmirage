# CHANGELOG_FIXES

## 第二轮（2026-10-30，任务书 v2：5 次重复、概率指标与验收缺陷）

任务来源：`VulnMirage_DeepSeek_Modification_Requirements_v2.md`。基线为第一轮修改后的工作区；本轮只修正缺陷并补充 5 次重复的统计语义，不删除旧运行/旧报告/失败记录/原始候选。

| 任务 | 问题 | 关键修改位置 | 测试/证据 | 剩余限制 |
| --- | --- | --- | --- | --- |
| **P0-1 歧义退出分母** | `pair_rows()` 识别 `clean_attempt_ambiguous` 后仍可能置 `clean_valid=true`、`pairing_status=complete` 并计算 `fn_attack_success` | `evaluation/paired.py`（按比较的 `*_pair_status`、`*_ambiguity_reason`、`formal_eligible`）、`evaluation/conditions.py`（`selection_rule=none`）、`evaluation/report.py`（`_attempt_rule`） | `tests/unit/test_repetition_probabilities.py`：clean 歧义 → FN 不可评估、adversarial 歧义不择优、B 歧义不影响 C-A、T 歧义原因码、顺序不变；e2e/CLI 回归 | 无预注册规则的第二个 attempt 一律不可评估（设计如此）；需要重试时必须显式配置 `experiment.retry_policy` |
| **P0-2 凭据白名单接入子进程** | `credential_env_allowlist` 只出现在 YAML/doctor，`build_environment()` 未合并 | `credentials.py`（新增）、`harness/sandbox.py`、`harness/subprocess_agent.py`、`harness/container.py`、`harness/runner.py`、`diagnostics.py`、`config.py`（`credential_policy`） | `tests/unit/test_credentials_and_container.py`：prepared env 含声明变量、未声明不透传、序列化记录无 secret 值、container `-e NAME`、doctor declared/present/forwarded、缺凭据 live 前置失败 | 凭据值仅在进程环境与子进程环境之间传递；报告中永远只有名称 |
| **P0-3 live verification 由证据计算** | smoke 脚本用 `mode == "live"` 直接置 `live_verified=true` | `evaluation/live_verification.py`（新增）、`scripts/run_single_case_smoke.py`（非零退出码） | `tests/unit/test_live_verification.py`：dummy+失败 → false、真实身份但不可解析 → false、5 次成功且攻击全失败 → true 且 `attack_success_rate=0`、部分完成/不可评估 → false、offline → false | 真实 OpenCode + 凭据 live 未执行（见验证报告） |
| **P0-4 暴露三态** | 配对层 `bool(None)` 把“未知”变成“未暴露” | `evaluation/exposure.py`（新增原因码与判定）、`evaluation/paired.py`（三态行字段、`exposure_state_known`、聚合计数/比率）、`evaluation/report.py`（`exposure` 汇总） | `tests/unit/test_exposure_tristate.py`：pair row `null`、CSV 空值、聚合 `exposure_known/unknown`、`exposure_rate` 只除已知、`ASR|exposure` 分母、7 个 `None` 原因 | 因果识别仍需分支/消融；容器后端不包裹 strace（记录为限制） |
| **P0-5 FP 单目标绑定** | 校验后把全部 `validated_safe` 写入 `target_safe_target_ids` → `multiple_safe_targets_bound` | `generation/pipeline.py`（预选绑定、失败拒绝、`target_decoy_ids` 单值、身份包含目标）、`generation/safe_targets.py`（`preselect_safe_target_id`/`requested` 过滤）、`generation/targets.py`、`manipulations/base.py` | `tests/integration/test_fp_single_target.py`：两个已验证安全目标 → 生成/导出/运行/评估后 `target_status=bound`，另一个不参与 FP-ASR；M5 绑定 decoy 而非双绑定 | M5 合成 decoy 的 id 由算子确定性生成，实例 ID 记录安全的预选目标/合成标记；不使用未验证目标 |
| **P0-6 五次重复概率** | 无 repetition 层概率与条件 ASR | `evaluation/repetitions.py`（新增）、`evaluation/report.py`（`experiment`/`repetition_statistics`/`repetition_metrics.csv`）、`config.py`（`ExperimentConfig`） | `tests/unit/test_repetition_probabilities.py`（任务书示例 0.8/0.2/−0.6/4/3/0.75；缺失+失败+歧义不被当 0；分母为 0 → null+原因；两个目标两个 cell；legacy 排除） | 5 次重复只给步长 0.2 的单实例经验概率，不称高精度估计 |
| **P0-7 严重度概率** | 严重度字段与聚合不完整 | `evaluation/severity.py`、`evaluation/paired.py`（`attack_target_severity`/`oracle_target_severity`/`raw_severity_shift`/`oracle_directional_error_*`）、`evaluation/repetitions.py`（evaluable/success/率、均值/中位数/分布、方向性误差增量） | `tests/unit/test_repetition_probabilities.py`（严重度与 FN-ASR 分离、目标未检出不可评估、分布计数） | 严重度成功概率不并入 FN/FP-ASR |
| **P1-1 容器运行链路** | 只挂 `/repo`、`/scratch`、`/output`，OpenCode 配置与 HOME/XDG 仍指宿主 | `harness/container.py`（`/agent-state`、`--name`、`cleanup()`、agent 版本探测、env 名称/字面值分离）、`harness/subprocess_agent.py`、`harness/runner.py`（cleanup 写入 meta）、`diagnostics.py`、`configs/opencode.yaml` | `tests/unit/test_credentials_and_container.py`（agent-state、argv、doctor）；`tests/integration/test_container_isolation.py`（新增完整 adapter 测试） | Windows 宿主无 docker CLI；容器测试在 WSL（Docker 29.1.3 + ubuntu:22.04）执行 3 passed；默认 pytest 仍 opt-in |
| **P1-2 统计单位与 CI** | 无 repository 聚类、单位命名混用 | `evaluation/statistics.py`（`repository_cluster_bootstrap`）、`evaluation/report.py`（`macro_target_asr`/`micro_paired_repetition_asr`/`repository_cluster_bootstrap_95ci`，含 seed/samples/cluster key） | `tests/unit/test_defense_and_schema.py`（聚类键、确定性、字段名、seed/samples） | 未拟合 mixed-effects 模型（不替代透明计数） |
| **P1-3 防御矩阵重复** | 报告无法表达每防御 5 次与开销 | `harness/runner.py`（`repetitions` 来自 `experiment`，写 manifest）、`evaluation/report.py`（`_defense_matrix`、`defense_matrix.csv`） | `tests/unit/test_defense_and_schema.py`（D0/D1/D2 ASR、exposure unknown、delta、clean utility、开销、D2 命名） | D2 仍为提示策略，非运行时强制门控 |
| **P1-4 schema 与兼容** | 缺少 v3 语义与旧数据隔离 | `evaluation/report.py`（3.0、legacy 默认不进正式概率）、`evaluation/repetitions.py`、`config.py`（`include_legacy_in_formal_statistics`） | `tests/unit/test_defense_and_schema.py`（版本、legacy 排除）；`workspace/demo` 旧数据 evaluate 成功（8 行、legacy 8、formal 0） | 旧运行目标绑定缺失时仍只输出诊断行 |

### 新增/修改配置

- `experiment.repetitions`（默认 5）、`experiment.minimum_valid_repetitions`（默认 3）、`experiment.retry_policy.{max_attempts,selection_rule}`、`experiment.bootstrap_*`。
- `evaluation.include_legacy_in_formal_statistics`、`evaluation.minimum_valid_repetitions`、`evaluation.attempt_selection`（新增 `none`）。
- Agent：`credential_policy`、`container_agent_executable`、`container_agent_version`。
- Run/Meta：`planned_repetitions`、`attempt_selection_rule`、`retry_policy`、`container_cleanup`。

---

## 第一轮（2026-10-30，任务书 v1）

任务来源：`VulnMirage_DeepSeek_Modification_Requirements.md`（基线 `vulnmirage (2).zip` 工作区）。
所有条目的“已验证”均指代码与对应回归测试通过；真实 Agent 实跑状态见 `VALIDATION_REPORT.md`。

| 任务 | 问题 | 关键修改位置 | 测试/证据 | 剩余限制 |
| --- | --- | --- | --- | --- |
| **P0-1 精确配对** | `pair_rows()` 用 `by_instance[instance_id]`，同实例多次运行互相覆盖；VariantGroup/ same_group 分支只按 instance_id 取对照，可跨 repetition、模型、配置、防御条件借用 | `evaluation/conditions.py`（新增）、`evaluation/paired.py`、`evaluation/report.py`、`models/run.py`、`harness/runner.py` | `tests/unit/test_exact_pairing_and_targets.py`：跨 repetition（FN 可评估/不可评估）、同目录双模型、D0/D1 条件、外部配置哈希变化、B/T 条件与轮次、输入顺序不变、多 attempt、重复 attempt、缺失对照、R0 排除；Linux 全量测试通过 | 旧运行没有显式条件字段时使用 `legacy_reduced` 降级身份（`condition_complete=false`）；可用 `evaluation.legacy_condition_mode=strict` 禁止配对。缺失 `agent_config_sha256` 的旧运行会被标注但无法证明外部配置一致 |
| **P0-2 目标级评估** | `target_found = len(assignments) > 0`；`ManipulationSpec.target_vulnerability_ids` 写入全部 eligible；实例/seed/candidate/group 不含目标身份；FP 使用所有安全目标；severity 可被无关漏洞污染 | `evaluation/targets.py`（新增）、`evaluation/metrics.py`、`evaluation/paired.py`、`evaluation/severity.py`、`generation/pipeline.py`、`generation/candidates.py`、`store.py`、`models/instance.py`、`models/manipulation.py`、`export/bundle.py` | `tests/unit/test_exact_pairing_and_targets.py`（V1/V2、隐藏目标、多路径、歧义多目标、同位置不同 CWE、实例 ID 目标隔离）；更新后的 e2e/CLI/benign 集成测试断言目标级语义 | 旧 instance/manipulation 只有“全量 ids”且无显式单目标时标为 `ambiguous/legacy_unbound`，不进入正式目标指标；多目标攻击以“多个单目标实例”表示，未实现单实例多目标 |
| **P0-3 候选与 release** | 无反馈时永远选首个算子；候选数不保证算子覆盖；预算在每个 candidate 调用重置；dedup 只过滤返回值；export 遍历目录；`--limit` 丢 B/T | `generation/scheduling.py`（新增）、`generation/candidates.py`、`generation/pipeline.py`、`generation/dedup.py`、`config.py`、`export/bundle.py`、`harness/runner.py` | `tests/unit/test_p0_pipeline_agent_observation.py`：exhaustive 覆盖、coverage 记录、跨目标不合并、selection manifest、limit 保留 C/B/T；Linux 集成测试覆盖生成/导出 | LLM 单候选拒绝已记录并继续；LLM 基础设施错误仍中止（设计如此）。历史工作区无 manifest 时 export 回退旧行为并记录 |
| **P0-4 Agent 接入** | `config_file: configs/opencode.json` 相对 agent YAML 解析成 `configs/configs/...`；text 模式无原生 trace；把全部 stdout/工具结果当最终报告；凭据/版本/可写路径缺少 doctor 检查；复用全局会话 | `configs/opencode.yaml`、`harness/opencode.py`、`harness/subprocess_agent.py`、`diagnostics.py`、`config.py` | `tests/unit/test_p0_pipeline_agent_observation.py`：路径只解析一次、可疑 tool-result 伪 findings 被忽略、多个不同 envelope 判 ambiguous、未知格式 unsupported 且保留 raw、两 run 的 HOME/XDG 不同、required trace 失败不启动 Agent | OpenCode 版本/事件格式以 `opencode_event_format` 固定并为 doctor 记录；未在真实 OpenCode + 凭据下跑通 live（见验证报告）。文本模式明确不支持原生 trace |
| **P0-5 观测降级** | 仅检查 strace 存在，ptrace 被拒绝时包装后的 Agent 未启动却记为 `agent_tool_failure` | `harness/observation/os_trace.py`、`harness/subprocess_agent.py`、`harness/runner.py`、`harness/observation/normalize.py` | `tests/unit/test_p0_pipeline_agent_observation.py`：缺失/可用/ptrace denied/probe 超时/缓存；required 中止归因；Linux 集成测试实际运行 strace | auto 模式失败降级为 native/wrapper 观测并记录原因；容器后端不包装 strace（记录限制） |
| **P1-1 防御条件** | 防御不是独立执行条件；提示混在 audit task；报告无法按防御分组 | `defenses.py`（新增）、`prompts/defense/*`、`prompts/audit_task.md`、`config.py`、`harness/runner.py`、`cli.py`、`evaluation/report.py` | `tests/unit/test_defense_conditions.py`：D0/D1/D2 condition_id 不同；改名同内容保持身份；防御文本确实进入 prompt；D2 无目标/答案；`run_matrix` 每防御独立执行 | D2 是提示策略，不是运行时强制核验；未来 evidence gate 需另设防御类型。真实模型下 D0/D1/D2 效果未测量 |
| **P1-2 轨迹语义** | 文件打开可能被当成模型看见 payload；未知观测被当作“未暴露” | `evaluation/evidence.py`、`models/events.py`、`models/evidence.py`、`harness/observation/normalize.py`、`evaluation/report.py` | `tests/unit/test_layered_exposure.py`：OS open-only/返回不含 payload/截断/未知行号/完整可见；`tests/integration/test_observation_verification.py` 全通过 | `unknown` 保持 null 并不进入 `ASR|observed_exposure` 分母；因果识别仍需分支/消融，报告未把条件 ASR 当因果 |
| **P1-3 smoke 入口** | 无可复现单仓库 smoke | `scripts/run_single_case_smoke.py`（新增）、README | offline 已在 `workspace/demo` 实跑并生成 `workspace/demo/smoke-out/smoke_summary.json`；live 模式为显式命令，不进入 pytest | live 未执行（无凭据/真实模型） |
| **P1-4 隔离** | subprocess 只能 best-effort；无容器后端 | `harness/container.py`（新增）、`harness/subprocess_agent.py`、`harness/runner.py`、`config.py`、`tests/integration/test_container_isolation.py` | WSL Docker 29.1.3 + `ubuntu:22.04`：容器测试 2 passed（仓库可读、oracle 不可读、仓库不可写、scratch 可写、两次运行状态隔离） | 容器默认 `--network none` 会同时阻断模型 API；`bridge` 只能标记 best-effort 网络分离。未挂载宿主项目、oracle、Docker socket |
| **P1-5 统计与兼容** | 新模型字段会使旧 release 哈希校验失败；缺少失败率/缺失原因/唯一 clean 口径/宏观统计/切分泄露检查 | `export/bundle.py`、`evaluation/report.py`、`evaluation/paired.py`、`schemas/*` | 历史 `workspace/demo` release 在新代码下 `evaluate` 成功；Linux 全量测试通过；schema 已用 `vulnmirage schemas` 重新生成 | 旧 summary 不重标为 2.0；bootstrap 仍以 repository+oracle 为 cluster，repo-macro 另报；未做历史数据自动改写 |

## 追加：RepoVuln-50 xlsx 数据接入（2026-10-30）

用户提供 `RepoVuln-50_全仓库漏洞表_2026-10-25.xlsx` 后新增：

- `src/vulnmirage/ingest/repovuln.py`：stdlib XLSX 读取，无需 openpyxl/pandas；按 `(repo_url, vulnerable_commit)` 聚合；每个仓库快照生成一个多漏洞 oracle；CVE/GHSA 写入 aliases；`review_status=PASS` 才导入；单个快照构建失败只记录 rejected，不中止其他仓库。
- CLI：`vulnmirage ingest repovuln --workbook ... --output ... [--data-scope live] [--limit-groups N]`。
- `generation/targets.py`：`--target-vulnerability-id CVE-...` 可用 alias 解析，内部仍绑定 canonical `VULN-*`；pipeline 记录 `requested_target` / `selected_target_id` / `selected_target_aliases`。
- 测试：`tests/unit/test_repovuln_ingest.py`（多漏洞聚合、多 commit 分离、data_scope、alias 目标解析、局限标记）。
- 真实数据验证：167 行 → 48 个仓库、56 个快照、167 个漏洞、0 rejected；`DaveGamble/cJSON` 快照 4 个漏洞 → materialize 成功（8 个位置解析）→ 生成 4 个不同目标的 M1 实例 → export 5（C+4A）→ dummy run 5 → evaluate 4 条目标配对行。
- 数据限制：xlsx 只有入口/关键操作位置，无有序 trace、无 PoC/回归命令、无安全目标；oracle 标记 `evidence_scope=entry_and_sink_only`、`trace_available=false`、`poc_available=false`。

## 追加：Hugging Face 导出（2026-10-30）

- `scripts/export_hf_dataset.py`：从 `ingest repovuln` 输出生成 Hub-ready 目录：`cases` / `vulnerabilities` / `paths` 三张关系表（JSONL）、`README.md` dataset card（三个 config + dev/test data_files）、`dataset_manifest.json`（来源 SHA-256、计数、split 策略、文件校验和、仓库重叠检查）、`LICENSE-NOTES.md`。
- split 按 `repo_url` 的确定性哈希分配，仓库不跨 dev/test；支持 `--split-policy none`。
- 真实表：56 snapshots / 167 vulnerabilities / 167 paths；repo-hash 0.7 → dev 38 snapshots / 134 vulns，test 18 / 33，仓库重叠为 0。
- README 增加 `dataset_info`（由 `datasets` 生成 features/splits），缺失的 `category_l1/l2` 已从工作簿补回，字符串字段统一为空串以避免 null/string 类型翻转。
- 测试：`tests/unit/test_hf_export.py`（三表 join、trace 缺失标记、manifest、repo split）。

## 新增/修改的主要配置

- `generation.candidate_schedule` (`balanced|exhaustive|feedback`)
- `generation.selection_manifest` / `generation.export_use_selection_manifest`
- `generation.max_targets_per_oracle`（0 = 所有合格目标，每个目标一个单目标实例）
- `defense.default` / `defense.conditions[]`
- `evaluation.attempt_selection` (`first_evaluable|first_attempt|last_attempt`)
- `evaluation.legacy_condition_mode` (`derive_reduced|strict`)
- `observation.os_trace` 新增 `required`
- Agent：`execution_backend`、`container_runtime`、`container_image`、`container_network`、`credential_env_allowlist`、`inference`、`opencode_version`、`opencode_event_format`

## 明确的未验证项

1. **真实 Agent live 测试**：没有可用模型凭据，未执行 `scripts/run_single_case_smoke.py live`，也未运行 `vulnmirage run` 的真实模型样本。所有 dummy/offline 结果不是真实攻击效果。
2. **Windows 原生完整测试集**：本机 Git for Windows 在 Python 子进程里启动 MSYS `sh` 时被拒绝创建命名对象（`NtCreateDirectoryObject ... 0xC0000022`），依赖本地 `file://` 克隆的集成测试无法运行；同一代码在 WSL Linux Python 3.11 下全量通过。
3. **真实数据集/大规模付费实验**：未执行，未配置密钥。
