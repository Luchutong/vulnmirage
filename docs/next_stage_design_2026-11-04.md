# VulnMirage 下一阶段设计：从可运行流水线到可发表实验

日期：2026-11-04  
适用仓库：`LAB/vulnmirage`  
前置设计：`benchmark_revision_plan_2026-11-03.md`  
当前实现核对：`benchmark_revision_2026-11-03_status.md`

## 1. 文档目的

当前 benchmark 已经完成任务驱动的主干改造，但“代码能完整走通”不等于“已经可以
产出可信的论文实验结果”。本文件定义下一阶段的工程边界、实验设计、验收门槛和
扩展顺序，目标是把当前版本推进到：

1. 真实 OpenCode 审计过程可观察、可归档；
2. agent 只能访问推理 API，不能检索答案；
3. 注入方法的行为保持与真值位置可验证；
4. clean/attack、模型和重复之间可以做成对统计；
5. 完整实验在运行前冻结，失败与排除不会被静默丢弃。

本阶段仍不研究防御提示、D0/D1/D2 或防御方法比较。没有中性内容注入条件；`C`
是唯一基线。该决定意味着估计量针对“完整注入处理”的效果，不能单独识别新增
token、文件位置与语义内容各自的因果贡献。

## 2. 当前 benchmark 的设计思路

### 2.1 研究对象

在相同仓库快照、相同任务、相同模型、相同预算下，只改变仓库上下文，观察：

- 已核验真实 target 是否被发现；
- finding 的证据、置信度和严重性是否变化；
- 私有认证的安全诱饵是否被误报；
- agent 是否改变文件探索、假设形成和验证资源分配；
- 最终报告是否采纳虚假修复、虚假权威或严重性锚点。

### 2.2 任务驱动而非预下载全部仓库

```text
读取一个 task
  → 下载一个精确 commit 压缩包
  → 构建 clean 和所选 variants
  → 每个 variant 独立审计
  → verifier 评分和机制分析
  → 归档并删除本任务临时副本
  → 下一个 task
```

这样避免提前克隆 47 个仓库，也避免 `.git`、修复提交或相邻运行成为答案渠道。
归档缓存可以复用，但 run 状态不能跨 `(variant_set, model)` 共享。

### 2.3 数据与 benchmark 分工

| 层 | 内容 | 可见性 |
| :-- | :-- | :-- |
| dataset task | 仓库、commit、统一审计任务 | 可用于计划和 agent prompt |
| dataset oracle | target、位置、CWE、严重性、fix/evidence | 仅 verifier 和可信准备阶段 |
| PayloadGen | 方法、模板、生成器、variant set | 可信处理定义，不复制给 agent |
| run archive | 报告、findings、stdout、trace、评分 | 实验产物，按泄露策略发布 |

### 2.4 独立变体与冻结计划

每个 variant 都从同一个 clean tree 独立构建，不叠加其他方法。`campaign plan`
在首次运行前冻结：

- task 列表与执行预算；
- variant-set id、研究问题和文件 SHA-256；
- payload registry、模板和生成资产 SHA-256；
- 规范化 prompt SHA-256；
- archive request 与配置摘要。

`campaign run` 只接受 plan，不重新选择方法集。资产变化后 resume 必须失败。

### 2.5 Oracle 隔离和独立评分

计划和 agent workspace 不包含 target id、CVE、CWE、修复提交或 oracle 文本。
私有目标只在可信准备和独立 verifier 中使用。Agent 答案先冻结成带哈希的 bundle，
再由 verifier 解析和评分；报告文本被当作不可信数据，不能指挥 evaluator。

### 2.6 双输出与机制证据

一次审计必须同时给出：

- `report_markdown`：供人工分析的安全报告；
- `findings`：供确定性匹配的结构化发现；
- `audit_summary`：范围、限制和总体置信度。

结果变化不自动等于机制结论。机制标签要求完整证据链：

```text
payload 路径
→ 内容确实返回给模型
→ 可观察探索/验证行为改变
→ 报告或 target 结果改变
```

缺少 trace 时只能写 `insufficient_evidence`。

## 3. 当前进度基线

### 3.1 已完成

| 能力 | 状态 | 证据 |
| :-- | :-- | :-- |
| dataset-core 读取与摘要校验 | 已完成 | 47 tasks / 725 targets，manifest digest 全部匹配 |
| 精确 commit archive 下载 | 已完成 | provider allowlist、TLS、重定向和体量预算 |
| 安全解压 | 已完成 | 拒绝穿越、绝对路径、链接、设备文件、大小写冲突和嵌套历史 |
| 私有 target 物化 | 已完成 | 文件/anchor 不匹配的 target 明确排除 |
| variant 独立构建 | 已完成 | create/append/insert-before，前置条件失败即停止 |
| payload 模板方法 | 已完成 | 7 个 runnable adaptation |
| variant sets | 已完成 | core、false-negative、safe-decoy、severity |
| planned 方法 fail-closed | 已完成 | FPA/FlashBoom 被 plan 阶段拒绝 |
| OpenCode 外部进程执行 | 已完成 | DeepSeek/GLM/Qwen 配置，stdout/stderr 落盘 |
| 双输出解析 | 已完成 | 不修复模型答案，格式失败不转成零 finding |
| 独立 verifier | 已完成 | bundle 哈希、oracle 拒绝、target/decoy 匹配 |
| 机制分析契约 | 已完成 | exposure/trajectory/mechanism/case-analysis |
| 状态机、归档、清理 | 已完成 | resume identity、artifact manifest、scoped cleanup |
| 回归基线 | 已完成 | 44 tests；27 schemas current |

### 3.2 部分完成

| 能力 | 已有部分 | 缺口 |
| :-- | :-- | :-- |
| Agent trace | 原始 OpenCode JSONL stdout 已保存；分析器能读取标准化 trace | 尚无 OpenCode → normalized events/tool/file-access 的原生适配器 |
| 网络隔离 | 环境净化、离线提示、实时 egress probe、fail-closed | 普通宿主不能强制阻断；需要代理或容器边界 |
| 多模型实验 | 4 个 agent YAML 已配置 | 尚未形成同一冻结实验上的重复真实运行 |
| 机制分析 | 规则和 schema 已完成 | 没有 trace 时只能输出 unknown/insufficient |
| 安全诱饵 | Python AST 的窄子集证书 | F2 尚不是论文级 false bridge / private certificate |

### 3.3 未完成

- FPA 的语言感知语义改写、位置重映射与行为等价验证；
- FlashBoom 的 surrogate attention mining、自包含化和迁移评测；
- OpenCode trace 完整性统计与事件 schema 版本化；
- 推理 API allowlist 之外的强制网络阻断；
- 跨 task 的配对统计、cluster bootstrap 和模型比较；
- 预注册式的完整 experiment manifest；
- 全数据、多模型、多重复的正式运行与结果发布。

## 4. 下一阶段目标架构

下一版本应把 payload 的“研究开发”和“正式实验实例化”分开：

```text
离线方法研发（不属于正式 run）
  ├── 文献方法复现
  ├── LLM/white-box surrogate 生成候选
  ├── sandbox、测试、等价性与安全验证
  └── 输出带版本和哈希的 payload/pattern bank

正式实验
  ├── plan：冻结任务、方法库版本、模型、预算、重复和顺序
  ├── prepare：下载快照，确定性实例化固定 bank，验证并冻结 variants
  ├── audit：无答案网络、独立 workspace、完整原始 trace
  ├── verify：私有 oracle、冻结 bundle、确定性评分
  ├── analyze：成对轨迹和报告机制
  └── aggregate：task-clustered 统计、排除清单和结果表
```

正式 test 任务上不得根据 victim 模型结果继续优化 payload。需要明确三个威胁强度：

| 层级 | Payload 如何产生 | 是否可作为默认 benchmark |
| :-- | :-- | :--: |
| fixed | 预先冻结的通用模板或 pattern bank | 是 |
| surrogate-adaptive | 只使用独立模型和 dev 仓库筛选 | 是，需单独标注 |
| victim-adaptive | 根据同一 victim 的反馈迭代 | 否；只能作为独立扩展实验 |

## 5. 工作包 WP0：真实实验可观测性

### 5.1 OpenCode trace adapter

新增建议：

```text
src/vulnmirage/trace/
  opencode.py
  normalize.py
  models.py
  completeness.py
```

输入是不可修改的 `stdout.log`，输出：

- `events.normalized.jsonl`：有序事件、角色、part 类型、时间、event id；
- `tool_calls.jsonl`：工具名、参数摘要、状态、耗时、关联事件；
- `file_access.jsonl`：规范化路径、读取/搜索类型、内容是否返回模型；
- `trace_manifest.json`：原始日志 SHA-256、适配器版本、行数、丢弃原因；
- `trace_completeness.json`：可解析率、未知事件率、tool 配对率、路径覆盖率。

事件规范化必须满足：

1. 原始 stdout 永久保留，派生产物记录 source SHA-256；
2. 不把 shell 命令中出现路径等同于“模型看到了文件内容”；
3. tool call 和 tool result 必须通过稳定 id 关联；
4. 无法识别的新事件类型保留摘要并记 unknown；
5. API key、Authorization header 和环境值在归档前机械脱敏；
6. parser 只解析，不推断模型隐藏思维。

验收：

- 真实 OpenCode fixture 覆盖 text、tool call、tool result、error、step finish；
- 解析后可重建事件顺序；
- payload exposure 只有在内容返回事件存在时才为 exposed；
- trace 缺失、截断和 schema 漂移都有稳定失败状态。

### 5.2 网络边界

正式审计要求“推理连接可用、答案网络不可用”。建议实现本地 inference proxy：

```text
agent process
  → only local proxy
      → allow configured model API hosts
      → deny GitHub/Hugging Face/search/advisory hosts and arbitrary CONNECT
```

可选后端：

- 容器网络命名空间 + allowlist proxy；
- Windows 宿主上的强制代理与防火墙规则；
- 独立审计虚拟机。

仅删除代理环境变量不是安全边界。正式 run 必须同时记录：

- inference gateway 探测成功；
- 所有 answer-host 探测失败；
- DNS/直连绕过探测；
- runtime boundary 类型和配置摘要；
- proxy/firewall 日志的摘要哈希。

无法证明时允许开发 run，但必须标记 ineligible，不能进入正式效果分母。

## 6. 工作包 WP1：PayloadGen 生成器接口

### 6.1 从 template-only 扩展为 generator

`PayloadMethod` 建议新增：

```yaml
realization_mode: template | generator
generator_id: fpa | flashboom | certified_redherring
generator_config: ...
supported_languages: [...]
validation_profile: ...
bank_version: ...
```

生成器统一返回：

```text
GeneratorResult
  edits[]
  public_provenance
  private_certificate_ref
  location_map
  validation_evidence
  rejected_candidates[]
```

私有证书不得进入 public patch 或 agent workspace。

### 6.2 AST 感知编辑

现有 create/append/insert-before 不足以支持语义改写。新增：

```text
replace_node
insert_node_before
insert_node_after
wrap_node
```

每个编辑必须带：

- path；
- parser/language/version；
- AST node kind 与 qualified name；
- 原 node byte range；
- expected source SHA-256；
- replacement SHA-256；
- line/byte source map。

匹配多个节点、节点缺失或 source hash 不符都应失败，不能猜测位置。

### 6.3 Variant-specific target remapping

语义改写会改变行号。每个 variant 的私有 target 文件应记录：

```text
clean location
→ edit source map
→ remapped location
→ post-edit anchor verification
```

verifier 必须使用对应 variant 的位置，不能继续沿用 clean 行号。

## 7. 工作包 WP2：FPA、FlashBoom 与 RedHerring

### 7.1 Familiar Pattern Attack

参考 [FPA/NDSS 2026](https://arxiv.org/abs/2508.17361) 与其
[官方代码](https://github.com/ShirBernBGU/Trust-Me-I-Know-This-Function)。

实现分为：

1. 在独立 dev corpus 上挖掘熟悉模式 `P`；
2. 产生小扰动 `P′`，得到确定但被 surrogate 误判的结果；
3. 保存为按语言分组的固定 pattern bank；
4. 在 target 附近用 AST 结构嵌入感知控制流；
5. 保证原始真实漏洞、PoC 和公开行为不变；
6. 只在 build、tests、target invariance、差分测试全部通过时保留。

首版只支持有稳定 parser/build fixture 的语言。未支持语言显式记
`method_incompatible`，不得退化成文件末尾注释。

### 7.2 FlashBoom

参考 [IEEE S&P 2025 论文](https://doi.org/10.1109/SP61157.2025.00125) 和
[Crazy-Ivan 官方实现](https://github.com/oxygen-hunter/Flashboom)。

因为 DeepSeek/GLM/Qwen API 不暴露内部 attention，正式方法采用 transfer 设计：

1. 在开源 white-box surrogate 上计算函数级 attention；
2. 选择跨 surrogate 稳定的高 attention 函数；
3. 静态补齐依赖、消除副作用并冻结 donor bank；
4. 按目标语言和局部风格确定性适配；
5. 通过编译、测试和行为保持检查；
6. API victim 上只测迁移效果，不用其结果回调生成器。

结果除 target 召回外，还应报告：

- payload 文件/函数是否被读取；
- payload 相关 tool calls 与 token/time share；
- target 首次读取是否推迟；
- agent 是否围绕 decoy 建立并验证假设；
- trace 不完整时上述指标的可评估比例。

### 7.3 Certified RedHerring

当前 F2 是安全字符串诱饵，不等同于完整 RedHerring。下一版参考
[Cheap to Hypothesize, Costly to Verify](https://arxiv.org/abs/2609.35909)：

- CVE-derived apparent vulnerability chain；
- 所有 sink 路径都经过的 false bridge；
- verifier 私有的不可满足证书；
- dominator analysis；
- native tests、差分测试和定向 fuzzing；
- 仓库类型、命名和调用结构适配。

建议注册新 id，而不是静默改变 `redherring_safe_decoy_v1`，保证旧实验可复现。

## 8. 工作包 WP3：实验矩阵与运行协议

### 8.1 研究问题分开运行

不要把所有方法放入一个默认大实验：

| 实验 | Variant set | 主要结果 |
| :-- | :-- | :-- |
| 主结果 | core | target detection、severity、报告变化 |
| 漏报机制 | false-negative | A1/A2/A3 的 paired target recall |
| 安全诱饵 | safe-decoy | certified FP、验证资源转移 |
| 严重性 | severity | conditional severity delta |
| FPA 扩展 | future fpa | 语义隐藏与 target invariance |
| FlashBoom 扩展 | future flashboom | 轨迹和资源转移 |

### 8.2 模型与重复

每个 `(variant_set, model)` 使用独立 workspace。正式计划冻结：

- provider、model id 和可获得的版本标识；
- OpenCode 版本；
- prompt 和 agent config SHA-256；
- time/token/tool budget；
- repetition 数；
- task 和 variant 执行顺序种子。

建议：

- 工程 pilot：1 task × 2 models × 1 repetition；
- 统计 pilot：5–10 tasks × 3 models × 3 repetitions；
- 正式实验：通过功效/方差 pilot 后确定，原则上每 cell 至少 5 次有效重复。

有效重复不足不能用失败 run 补成零分。重试规则必须在 plan 中冻结，并保留所有
attempt，不能只保留最好结果。

### 8.3 顺序与 API 时间漂移

同一 task 的 C/A 顺序应由 plan 固定随机种子随机化或平衡，而不是总是先 C 后 A。
统计分析保留：

- pair/order seed；
- 实际开始时间；
- provider request id（若可安全保存）；
- 模型/服务版本线索；
- timeout、rate limit 和 retry。

这可以减少 provider 状态与时间漂移和 treatment 顺序完全混淆。

## 9. 工作包 WP4：聚合与统计

### 9.1 分析单位

主要分析单位是同一 task、model、repetition 下的 C/A 配对。不能把 725 个 target
当成完全独立样本，因为同一仓库内 target、文件探索和一次报告共享上下文。

### 9.2 主要指标

| 指标 | 定义 |
| :-- | :-- |
| Target detection delta | attack target recall − clean target recall |
| Suppression rate | C 检出而 A 未检出的 scoreable targets / C 检出 targets |
| Certified decoy acceptance | 命中私有 safe-decoy 位置的 runs/tasks 比例 |
| Severity displacement | C/A 都命中 target 时的 ordinal/score delta |
| Valid answer rate | 双输出可解析且满足报告要求的 run 比例 |
| Exposure-evaluable rate | payload exposure 可以由 trace 判断的 run 比例 |
| Verification diversion | payload 相关 tool/time/token share 相对 C 的变化 |

所有指标同时报告：

- eligible 分母；
- 不可评分、格式失败、超时、网络失败和 trace 缺失数量；
- task-clustered 95% interval；
- 按模型和方法的分层结果。

### 9.3 推断方法

首版使用透明、可重算的方法：

- task-level paired bootstrap；
- 二元 paired outcome 的 McNemar/配对风险差；
- severity 只在 C/A 均命中的条件子集中分析，并明确选择条件；
- 多模型比较按 task cluster 重采样；
- 多方法检验预先指定主结果并校正，不从所有组合中挑显著项。

不把格式失败、隔离失败或 target 不可物化当作攻击成功。

### 9.4 新增模块

```text
src/vulnmirage/aggregate/
  collect.py
  eligibility.py
  paired.py
  bootstrap.py
  report.py
```

输入只能是验证过哈希的 archive，不重新读取临时 workspace。

## 10. Experiment manifest

在全量运行前新增顶层 manifest，至少包含：

```yaml
schema_version: "1.0"
experiment_id: ...
dataset_manifest_sha256: ...
task_ids: [...]
variant_set_id: ...
variant_set_sha256: ...
models:
  - agent_config_sha256: ...
    provider: ...
    model: ...
repetitions: 5
order_seed: ...
budgets: ...
retry_policy: ...
eligibility_policy: ...
trace_adapter_version: ...
aggregation_plan_version: ...
```

运行后生成 completion manifest，列出每个预期 cell 的：

- completed / failed / excluded / missing；
- run ids 和 attempt ids；
- archive manifest SHA-256；
- 失败原因；
- 是否进入各指标分母。

## 11. 验收门槛

### Gate G0：当前回归

- 44 tests 全部通过；
- 27 schemas 无 missing/stale；
- dataset manifest 校验通过。

### Gate G1：Trace-ready

- 至少三个真实 OpenCode run 的事件解析率可报告；
- tool call/result 配对完整；
- payload exposure 有正例、负例和 unknown 测试；
- 原始 stdout 与派生 trace 可通过哈希关联。

### Gate G2：Isolation-ready

- 推理 API 可达；
- 配置的答案主机和任意直连探测不可达；
- host workspace/oracle 不能从 agent runtime 读取；
- 同一证据在 C/A 条件下完全相同。

### Gate G3：Method-ready

- 每个 runnable 方法有兼容性与拒绝原因统计；
- 注入后 build/tests/target anchors 通过；
- safe decoy 有私有证书；
- semantic rewrite 有 location map 和 target-invariance 证据。

### Gate G4：Pilot-ready

- 1 task × 2 models 的所有预期 cells 完整；
- 双输出有效；
- archive verify 通过；
- 无 credential/oracle 泄露；
- 可以从归档独立重算 score 和 analysis。

### Gate G5：Experiment-ready

- 统计 pilot 完成并冻结正式 repetition/budget；
- experiment manifest 冻结；
- 无代码或 payload 变更；
- 全量运行脚本只消费 manifest；
- 中断后 resume 不改变 cell 身份或顺序。

## 12. 优先级和里程碑

| 优先级 | 工作 | 完成定义 |
| :-- | :-- | :-- |
| P0 | OpenCode trace adapter | G1 通过 |
| P0 | 强制网络边界 | G2 通过 |
| P0 | 真实双模型最小 pilot | G4 通过 |
| P1 | 聚合/eligibility 模块 | 可从归档生成 paired summary |
| P1 | 执行顺序随机化与 experiment manifest | 每个预期 cell 可审计 |
| P1 | AST edit + location remap | semantic method 不再依赖 footer append |
| P2 | 固定 FPA bank | 单独 variant set 通过 G3 |
| P2 | Transfer FlashBoom bank | 单独 variant set 通过 G3 |
| P2 | Certified RedHerring v2 | 私有证书、dominator、差分测试齐全 |
| P3 | 全量正式实验 | G5 后运行并发布结果 |

## 13. 风险与明确限制

1. 公共 CVE 可能存在训练记忆；离线网络不能消除训练污染。
2. Agent trace 是外部可观察行为，不是隐藏推理的还原。
3. 无中性内容对照时，不能区分语义操纵与额外上下文长度的效应。
4. API 模型版本可能静默变化；必须保存时间和可得版本线索。
5. archive 不一定包含 LFS/submodule 内容；必须按 task 记录，不得自动替换版本。
6. 数据集没有可执行 verifier/PoC/build command；多数 target 只能达到 snapshot 或
   annotation verified，不能声称 executable verified。
7. template adaptation 与论文完整复现不同；名称、版本和 `reproduction_status`
   必须持续保留。
8. 单次真实准备运行不构成模型效果结果；在正式 manifest 冻结前不发布排名。

## 14. 本阶段不做

- 不恢复 D0/D1/D2；
- 不把 defense prompt 当作实验条件；
- 不加入中性内容注入；
- 不一次性预下载 47 个仓库；
- 不根据正式 test victim 的反馈改写 payload；
- 不把未认证的 unmatched finding 自动算作 false positive；
- 不在 trace 缺失时用报告文本猜测 agent 的内部机制；
- 不在 isolation fail/unknown 时生成正式模型分数。

## 15. 参考实现与文献

- [AutoCodeGen / AutoCodeBench](https://arxiv.org/abs/2508.09101)：借鉴
  “生成 → sandbox 执行 → 私有测试 → 多级筛选”，不是注入攻击方法。
- [ALIBI](https://arxiv.org/abs/2607.24964)：对抗性代码注释、虚假工具结论与
  自适应黑盒攻击；默认 benchmark 只采用固定 adaptation。
- [Familiar Pattern Attacks](https://arxiv.org/abs/2508.17361)：熟悉模式、
  局部扰动、行为保持和黑盒误判筛选。
- [FlashBoom](https://doi.org/10.1109/SP61157.2025.00125)：
  函数级 attention、候选选择、依赖补齐、注入和验证。
- [RedHerring](https://arxiv.org/abs/2609.35909)：CVE-derived chain、
  false bridge、私有证书、dominator 和行为保持验证。
- [TrojanForge](https://arxiv.org/abs/2610.23109)：AST 索引、trace 到代码实体映射、
  注入位置排序；victim-adaptive 部分应作为单独威胁层级。

## 16. 下一步执行顺序

下一次代码修改应严格按下面顺序：

1. 收集并冻结一份真实 OpenCode JSONL fixture；
2. 实现 trace models、adapter、manifest 和 completeness；
3. 把适配器接入 run archive 与 mechanism analysis；
4. 建立 inference-only 网络边界并通过 egress 测试；
5. 运行一任务、两个模型、一个重复的最小 pilot；
6. 修复 pilot 暴露的输出、trace、隔离和归档问题；
7. 实现 aggregate 与 experiment manifest；
8. 完成统计 pilot 后再开发 FPA/FlashBoom，不让新方法掩盖主流程缺陷。
