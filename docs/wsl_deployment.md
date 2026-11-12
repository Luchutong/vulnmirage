# VulnMirage WSL 部署与单仓库实验

本文面向 WSL2/Linux 原生 OpenCode 2.x。目标是把项目和数据集复制到 WSL 的
Linux 文件系统后，完成环境检查、任务规划、候选生成、隔离审计、评分和归档。
所有命令都从项目根目录执行，不在配置文件中保存本机绝对路径。

> 当前 Linux namespace 后端已经完成代码与单元测试，但尚未替操作者执行模型
> 后端的正式验收。第一次运行应先检查 `network_boundary_probe.json`，再把结果
> 计入实验。不要在 Windows 目录中直接执行正式实验。

## 1. 运行边界

审计阶段的网络路径是：

```text
OpenCode（rootless user + network namespace）
  ├── 只有 lo，没有默认路由
  └── 127.0.0.1:18765
        → namespace 内 TCP relay
        → 私有 Unix socket
        → benchmark inference gateway
        → allowlist 中的模型 API
```

仓库下载发生在可信准备阶段，不在 agent namespace 内。审计阶段 OpenCode 不能
直接连接 GitHub、Hugging Face、搜索引擎或任意公网地址。Gateway 只转发
`configs/opencode.json` 中声明且同时出现在
`isolation.egress.inference_gateway_hosts` allowlist 中的 HTTPS provider。

该后端解决的是网络出口隔离。文件系统方面仍依赖单 run exposed workspace、
oracle 不落入工作区，以及 OpenCode 的 `external_directory: deny`；它不是完整的
mount namespace 或虚拟机文件系统隔离，不能把网络证明误写成宿主文件系统证明。

## 2. 复制到 WSL Linux 文件系统

不要把正式 workspace 放在 `/mnt/c` 或 `/mnt/d`。Windows 挂载盘的权限、路径
语义和 I/O 行为与 Linux 文件系统不同，也会增加宿主路径暴露面。

在 WSL 中执行：

```bash
mkdir -p ~/VulnMirageLab

cp -a '/mnt/d/download/hq/Agent repos injection/LAB/vulnmirage' \
  ~/VulnMirageLab/

cp -a '/mnt/d/download/hq/Agent repos injection/VulnMirage_dataset' \
  ~/VulnMirageLab/

cd ~/VulnMirageLab/vulnmirage
```

复制后预期布局为：

```text
~/VulnMirageLab/
├── vulnmirage/
└── VulnMirage_dataset/
```

这与 `configs/experiment.yaml` 默认的
`dataset_root: ../VulnMirage_dataset` 一致。

## 3. 系统依赖

需要：

- Python 3.11 或更高版本；
- `unshare`（通常来自 `util-linux`）；
- `ip`（通常来自 `iproute2`）；
- Git、CA 证书和原生 Linux OpenCode 2.x。

Ubuntu/WSL 的基础工具可安装为：

```bash
sudo apt update
sudo apt install -y util-linux iproute2 git ca-certificates
```

确认 Python 版本；如果系统仍是 3.10，请先通过你使用的 Python 管理方式安装
3.11/3.12，不要绕过项目的版本要求：

```bash
python3 --version
python3 -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
```

创建独立环境并安装项目：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

每次打开新的 WSL shell 后先执行：

```bash
cd ~/VulnMirageLab/vulnmirage
source .venv/bin/activate
```

## 4. 确认使用原生 Linux OpenCode

如果 OpenCode 安装在 `~/.opencode/bin`，先把它放在 Windows PATH 之前：

```bash
export PATH="$HOME/.opencode/bin:$PATH"
hash -r
```

需要长期生效时，把同一条 `export` 写入 `~/.bashrc`。然后检查：

```bash
type -a opencode
command -v opencode
file "$(command -v opencode)"
opencode --version
```

必须满足：

- 路径位于 Linux 文件系统，例如 `~/.opencode/bin/opencode`；
- `file` 输出包含 `ELF 64-bit`；
- 不能解析到 `/mnt/.../opencode`、`.cmd` 或 Windows `.exe`；
- 正式实验应冻结并记录 OpenCode 的准确版本。

未验证版本仍可运行，但 trace 会明确标记为 `unvalidated/partial`，不能用于正式的
机制结论。

## 5. 检查 rootless namespace

不要用 `sudo` 运行整个 benchmark。Agent namespace 应由普通用户通过 user
namespace 创建：

```bash
command -v unshare
command -v ip

unshare --user --map-root-user --net --mount-proc sh -c '
  ip link set lo up
  printf "interfaces="
  ls /sys/class/net
  printf "routes="
  ip route show
'
```

预期只显示 `lo`，且没有 default route。如果出现 `Operation not permitted`，说明
当前 WSL 发行版禁止非特权 user namespace。应检查发行版策略和
`kernel.unprivileged_userns_clone`；不要把 `fail_closed` 改成 `false` 来掩盖它。

## 6. 输入 API key

创建本地凭据文件：

```bash
cp .env.example .env
chmod 600 .env
```

编辑 `.env`，只需为即将运行的 profile 设置真实值。例如：

```dotenv
DEEPSEEK_API_KEY=你的真实key
```

不要把 key 写入 `configs/opencode.json`、YAML、命令行或 Git。Benchmark 只在
子进程环境中转发选中 profile 声明的变量，归档中只记录变量名。

Profile 与变量对应关系：

| `--agent-profile` | 环境变量 |
| --- | --- |
| `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `deepseek-reasoner` | `DEEPSEEK_API_KEY` |
| `glm-4.7` | `ZHIPU_API_KEY` |
| `qwen3-coder-plus` | `DASHSCOPE_API_KEY` |

## 7. 不调用模型的部署检查

以下检查不会提交审计 prompt，也不会产生模型 token 费用：

```bash
python -m vulnmirage doctor \
  --config configs/experiment.yaml \
  --agent configs/opencode.yaml \
  --agent-profile deepseek-chat

python -m vulnmirage ingest dataset-core \
  --root ../VulnMirage_dataset

python -m vulnmirage schemas
```

`doctor` 应确认：

- Python/配置/数据集可读取；
- `opencode`、`unshare`、`ip` 可执行；
- 所选 credential 名存在；
- inference upstream 从可信 gateway 一侧可达。

`doctor` 不能替代每个 run 的 namespace 证据。真正的 namespace、loopback relay
和公网直连阻断会在 audit 前逐 run 验证。

## 8. 冻结一个仓库任务

下面使用核心 O-FN 集合、一个 task、一个 target、一次 repetition。默认 core
集合包含一个 clean 条件和三个攻击条件，因此会产生四次审计，而不是一次模型
调用。

先只解析并检查计划：

```bash
python -m vulnmirage campaign plan \
  --config configs/experiment.yaml \
  --dataset ../VulnMirage_dataset \
  --variant-set PayloadGen/variant_sets/core.yaml \
  --workspace workspace/campaigns/core/deepseek-chat \
  --limit 1 \
  --target-limit 1 \
  --dry-run
```

确认输出后去掉 `--dry-run`，写入冻结计划：

```bash
python -m vulnmirage campaign plan \
  --config configs/experiment.yaml \
  --dataset ../VulnMirage_dataset \
  --variant-set PayloadGen/variant_sets/core.yaml \
  --workspace workspace/campaigns/core/deepseek-chat \
  --limit 1 \
  --target-limit 1
```

计划路径为：

```text
workspace/campaigns/core/deepseek-chat/control/plan.json
```

## 9. 下载、注入和审查候选（不调用模型）

```bash
python -m vulnmirage campaign generate \
  --config configs/experiment.yaml \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json \
  --inspect-generation
```

该阶段会联网下载精确 commit archive，但不会运行 OpenCode 或调用模型。检查：

- source commit 与 archive SHA-256；
- target eligibility；
- 每个候选的 edit、validator 和 rejection reason；
- selected candidate 与 generation manifest；
- clean/attack 是否从同一 clean tree 独立构建。

## 10. 开始真实审计

下面的命令会调用模型 API并产生费用：

```bash
python -m vulnmirage campaign run \
  --config configs/experiment.yaml \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json \
  --agent configs/opencode.yaml \
  --agent-profile deepseek-chat
```

每个 run 的顺序是：

1. 创建独立 exposed repo、output 和 state；
2. 启动 namespace preflight；
3. 只有 preflight 产生 `enforced_blocked` 才启动 OpenCode；
4. 创建仅指向本地 gateway 的 `opencode.runtime.json`；
5. 执行审计并记录原始 JSONL；
6. 规范化 trace、解析报告、私有评分、归档；
7. 验证 archive 后删除该任务的临时工作副本。

中断后使用同一条命令即可 resume。已存在冻结 `run.json` 的调用不会重复付费。

## 11. 检查网络与审计产物

先列出 run：

```bash
find workspace/campaigns/core/deepseek-chat/archives \
  -path '*/runs/*/run.json' -print
```

每个 `runs/<run-id>/` 至少应包含：

```text
network_boundary_probe.json
network_boundary.json
opencode.runtime.json
isolation_attestation.json
stdout.log
stderr.log
trace_manifest.json
trace_completeness.json
events.normalized.jsonl
tool_calls.jsonl
file_access.jsonl
final_raw.txt
agent_report.md
findings.json
run.json
meta.json
```

若安装了 `jq`，检查网络证据：

```bash
jq '{backend, network_namespace_distinct, interfaces, loopback_only,
     default_routes, external_connect_blocked, relay_reachable,
     enforcement_verified}' \
  workspace/campaigns/core/deepseek-chat/archives/<task-id>/runs/<run-id>/network_boundary.json
```

正式有效 run 必须同时满足：

```text
network_namespace_distinct = true
interfaces                 = ["lo"]
loopback_only              = true
default_routes             = []
external_connect_blocked   = true
relay_reachable            = true
enforcement_verified       = true
```

继续检查：

```bash
jq '{execution_status, isolation_eligibility, trace_status,
     trace_completeness, framework_version}' \
  workspace/campaigns/core/deepseek-chat/archives/<task-id>/runs/<run-id>/run.json

jq '{framework, framework_version, compatibility_status, status,
     parsed_events, invalid_lines, unknown_event_types}' \
  workspace/campaigns/core/deepseek-chat/archives/<task-id>/runs/<run-id>/trace_manifest.json
```

最后验证完整归档：

```bash
python -m vulnmirage campaign verify-archive \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json

python -m vulnmirage campaign status \
  --plan workspace/campaigns/core/deepseek-chat/control/plan.json
```

## 12. 常见错误

### `opencode` 指向 `/mnt/...` 或 Windows executable

PATH 顺序错误。重新执行：

```bash
export PATH="$HOME/.opencode/bin:$PATH"
hash -r
file "$(command -v opencode)"
```

### `linux_namespace agent runtime must be launched inside WSL/Linux`

命令仍在 Windows Python 中运行。进入 WSL 中复制后的项目目录，并激活 WSL 内的
`.venv`。

### `unshare: Operation not permitted`

非特权 user namespace 被禁用。检查 WSL/发行版策略。该错误属于隔离失败，不能
通过关闭 `fail_closed`、改回普通 subprocess 或使用 `sudo` 跑完整实验来忽略。

### `ip: command not found`

安装 `iproute2`。

### `no configured inference upstream is reachable`

可信 gateway 一侧无法连接所选模型 API。检查 WSL DNS、TLS、系统时间和 provider
域名；不要给 agent namespace 添加默认路由。

### `provider baseURL is not an allowlisted HTTPS inference endpoint`

`configs/opencode.json` 的 provider host 与
`configs/experiment.yaml` 的 `inference_gateway_hosts` 不一致，或者使用了非 HTTPS
upstream。修改正式配置后必须重新生成 plan，不能复用旧 plan。

### `ineligible_isolation`

先看 `network_boundary_probe.json` 和 `isolation_attestation.json`。隔离失败的 run
不能进入效果指标分母。

### `missing_answer` / `format_failure`

模型没有返回要求的 JSON envelope。查看 `stdout.log`、`stderr.log` 和
`final_raw.txt`；不要手工修复后当作有效结果。

### `compatibility_status: unvalidated`

当前 OpenCode 版本没有冻结的真实 CLI fixture。该 trace 只能作为 `partial`，不能
用于机制结论，直到为该版本生成并审核 fixture。

## 13. 正式扩展前

单任务 pilot 通过后再进行：

1. 至少三个模型后端 live run，报告 trace 完整率；
2. 每个模型使用独立 workspace；
3. 将 repetitions 提升到预注册值；
4. 冻结模型、OpenCode 版本、variant set、预算和 exclusion rule；
5. 验证所有 archive 可在不调用模型的情况下重新评分；
6. 最后才扩展到更多 task，避免把基础设施故障混入攻击效果。

