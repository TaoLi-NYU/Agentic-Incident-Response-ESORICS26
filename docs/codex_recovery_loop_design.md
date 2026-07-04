# Codex 辅助恢复闭环设计

本文记录一个建议架构：把 GCP VM 上的 A100、本地微调模型、高层恢复规划器、Codex/OpenAI 命令生成、`llm_ir_dt_new` 数字孪生环境连接成一个可执行、可验证、可计时的恢复闭环。

## 目标

目标是构建如下闭环：

1. 在 GCP VM 的 A100 GPU 上运行本地微调模型。
2. 由高层规划器为受影响服务器生成多个 high-level recovery actions。
3. 由 Codex/OpenAI 作为命令生成 agent，把每个 high-level action 转换成底层 bash command plan。
4. 在 GCP VM 中执行 bash commands；优先在 `llm_ir_dt_new` 的 Docker 数字孪生容器中执行。
5. 收集命令执行结果、恢复状态变化和恢复时间。
6. 把真实测得的恢复时间返回给高层规划器。
7. 选择恢复时间最短且验证通过的候选 action。
8. 重复执行，直到目标服务器或整个 incident 达到期望恢复状态。

关键原则是：Codex 不应该直接、无限制地控制整台 VM。Codex 应该输出结构化 command plan，项目代码负责校验、执行、计时和验证。

## 推荐的 High-Level Planner

当前的 `src/llm_recovery/decision_transformer/planner.py` 可以保留作为通用 high-level planner 的参考，但在这个项目里，更合适的起点是：

- `examples/predict_llm_ir_dt_new_initial_states_server.py`

原因是你的恢复任务需要按服务器分别处理，而不是只生成一个全局动作序列。模型需要先判断：

- 是否存在 incident；
- 涉及哪些 MITRE ATT&CK tactics；
- 涉及哪些 entities；
- 哪些服务器是 targeted servers；
- 哪台服务器应该优先恢复；
- 每台受影响服务器的初始六状态 recovery state 是什么。

当前 digital twin 中有这些服务器角色：

- `server_ssh` / `10.0.2.11`
- `server_samba` / `10.0.2.12`
- `server_shellshock` / `10.0.2.13`
- `server_web1` / `10.0.2.14`
- `server_web2` / `10.0.2.15`

因此 planner 应该生成 server-scoped high-level actions。例如：

```json
{
  "server": "server_ssh",
  "server_ip": "10.0.2.11",
  "current_state": {
    "is_attack_contained": false,
    "is_knowledge_sufficient": false,
    "are_forensics_preserved": false,
    "is_eradicated": false,
    "is_hardened": false,
    "is_recovered": false
  },
  "candidate_actions": [
    "通过 gateway 阻断攻击主机访问 SSH server。",
    "导出 SSH server 的认证日志和账号信息作为证据。",
    "禁用弱口令 SSH 登录并重启 SSH 服务。"
  ]
}
```

第一版确认采用 `planning_simulation_qwen_lora_DTserver.py` 的 high-level action 采样逻辑：在当前 server-scoped recovery state 下，由 A100 上的本地微调模型生成多个 candidate actions。需要做两个小修订：

1. 模型输出如果是 JSON，优先解析 `"Action"` 和 `"Explanation"` 字段，而不是把整段 JSON 当成 action 文本。
2. 保存完整 `raw_model_output`，用于调试、审计和复现实验，但后续 Codex command agent 默认只使用解析后的 `action` 和 `explanation`。

建议 candidate action 的内部结构为：

```json
{
  "action": "Block attacker traffic from 10.0.1.11 to 10.0.2.11 at the gateway.",
  "explanation": "This contains the attack affecting the prioritized SSH server.",
  "raw_model_output": "{\"Action\": \"Block attacker traffic from 10.0.1.11 to 10.0.2.11 at the gateway.\", \"Explanation\": \"This contains the attack affecting the prioritized SSH server.\"}"
}
```

其中：

- `action`：给 Codex/OpenAI command agent 使用的干净 high-level action。
- `explanation`：给 command agent 和 artifact 使用的动作理由。
- `raw_model_output`：只用于日志、调试、审计和复现实验，不作为主要决策字段。

## 建议新增模块

建议新增以下模块。它们可以放在 `src/llm_recovery/recovery_loop/`，也可以放在 `llm_ir_dt_new/src/llm_ir_dt/recovery_loop/`。考虑到第一阶段应优先在数字孪生环境中跑通，建议先放在 `llm_ir_dt_new` 下面。

### `command_agent.py`

职责：

- 调用 Codex/OpenAI 或其他命令生成模型。
- 把一个 server-scoped high-level recovery action 转换成结构化 command plan。

第一版已经支持三种 command agent：

- `MockCommandAgent`：根据 high-level action 返回预设 command plan，适合 smoke test 和排查 Docker/digital twin 问题。
- `OpenAICommandAgent`：调用 OpenAI Responses API，把 high-level action 转换成结构化 command plan，适合正式闭环实验。
- `DeepSeekCommandAgent`：调用 DeepSeek Chat Completions API，把 high-level action 转换成结构化 command plan。当前默认模型为 `deepseek-v4-pro`。

mock/stub 的闭环如下：

```text
high-level action
  -> mock command_agent 返回预设 bash commands
  -> command_safety 校验
  -> recovery_executor 执行
  -> state_verifier 验证
  -> baseline_manager 重建环境
  -> planner 选择最优 action
```

代码接口为：

```text
CommandAgent
  -> MockCommandAgent
  -> OpenAICommandAgent
  -> DeepSeekCommandAgent
```

可以通过配置选择 mock：

```bash
--command-agent mock
```

也可以切换为 OpenAI API：

```bash
--command-agent openai
```

也可以切换为 DeepSeek API：

```bash
--command-agent deepseek
```

正式运行前需要在 VM 中设置 API key，例如：

```bash
export OPENAI_API_KEY="你的 OpenAI API key"
export DEEPSEEK_API_KEY="你的 DeepSeek API key"
```

当前 DeepSeek V4 Pro 脚本示例：

```bash
cd ~/llm-recovery-dt/llm_ir_dt_new

/home/yu3194924316/llmrec-py311-env/bin/python run_recovery_loop_mock.py \
  --action-provider local-model \
  --command-agent deepseek \
  --deepseek-model deepseek-v4-pro \
  --adapter ~/llm-recovery-dt/models/checkpoint-850 \
  --system-file inputs/system.txt \
  --logs-file inputs/logs.txt \
  --incident-file inputs/incident.txt \
  --num-candidates 3 \
  --max-plan-steps 1 \
  --max-rollout-depth 1 \
  --wait-seconds 15
```

输入示例：

```json
{
  "system": "...digital twin topology...",
  "logs": "...Snort alerts and host logs...",
  "server": "server_ssh",
  "server_ip": "10.0.2.11",
  "attacker_ip": "10.0.1.11",
  "current_state": {
    "is_attack_contained": false,
    "is_knowledge_sufficient": false,
    "are_forensics_preserved": false,
    "is_eradicated": false,
    "is_hardened": false,
    "is_recovered": false
  },
  "high_level_action": "通过 gateway 阻断攻击主机访问 SSH server。",
  "high_level_action_explanation": "该动作可以先阻断攻击源到目标 SSH server 的连接，推进 containment 状态。"
}
```

输出示例：

```json
{
  "commands": [
    {
      "container": "gateway",
      "command": "iptables -I FORWARD -s 10.0.1.11 -d 10.0.2.11 -j DROP",
      "allowed_exit_codes": [0],
      "description": "Block attacker traffic to the SSH server."
    }
  ],
  "verification_commands": [
    {
      "container": "gateway",
      "command": "iptables-save",
      "allowed_exit_codes": [0],
      "description": "Show active gateway firewall rules."
    },
    {
      "container": "client",
      "command": "ping -c 2 10.0.2.11",
      "allowed_exit_codes": [1, 2],
      "description": "Confirm client connectivity to the target is blocked."
    }
  ],
  "expected_state_change": {
    "is_attack_contained": true,
    "is_knowledge_sufficient": false,
    "are_forensics_preserved": false,
    "is_eradicated": false,
    "is_hardened": false,
    "is_recovered": false
  },
  "rollback_commands": []
}
```

这里的输出必须是 JSON。executor 不应该接受自由文本形式的 shell 命令。

### `command_safety.py`

职责：

- 在执行前校验 Codex 生成的命令。
- 拒绝危险、无关、越界或不符合实验范围的命令。

建议校验规则：

- 只允许操作已知容器：`gateway`、`client`、`server_ssh`、`server_samba`、`server_shellshock`、`server_web1`、`server_web2`。
- 当前第一版 allowlist：`apachectl`、`cat`、`chmod`、`cp`、`curl`、`find`、`grep`、`head`、`ip`、`iptables`、`iptables-save`、`ls`、`mkdir`、`nginx`、`passwd`、`pgrep`、`ping`、`pkill`、`ps`、`sed`、`service`、`ss`、`sshd`、`tar`、`test`、`touch`、`true`、`uname`。
- 拒绝 `rm -rf /`、磁盘格式化、修改宿主机权限、从任意 URL 下载并执行脚本、反向 shell、凭据外传、写入非批准 artifact 目录等行为。
- 每个 command plan 必须包含 verification commands。
- 对网络阻断、服务配置修改这类动作，尽可能要求 rollback commands。

### `recovery_executor.py`

职责：

- 执行通过校验的 command plan。
- 测量恢复动作耗时。
- 收集每条命令的 stdout、stderr、exit code。
- 把结构化执行结果返回给 planner。

第一阶段建议 executor 使用：

- `llm_ir_dt_new/src/llm_ir_dt/docker_manager/docker_manager.py`

这样命令会执行在 digital twin 容器内部，而不是直接执行在宿主 GCP VM 上。

执行结果示例：

```json
{
  "server": "server_ssh",
  "high_level_action": "通过 gateway 阻断攻击主机访问 SSH server。",
  "success": true,
  "action_execution_time_seconds": 0.22,
  "action_verification_time_seconds": 2.04,
  "action_total_time_seconds": 2.26,
  "rollout_total_time_seconds": 8.0,
  "baseline_restore_time_seconds": 60.0,
  "wall_clock_time_seconds": 68.0,
  "command_results": [
    {
      "container": "gateway",
      "command": "iptables -I FORWARD -s 10.0.1.11 -d 10.0.2.11 -j DROP",
      "exit_code": 0,
      "output": "",
      "elapsed_seconds": 0.18
    }
  ],
  "verification_results": [
    {
      "container": "gateway",
      "command": "iptables -S",
      "exit_code": 0,
      "output": "...",
      "elapsed_seconds": 0.03
    }
  ]
}
```

时间字段约定：

- `action_execution_time_seconds`：当前 high-level action 对应底层 recovery commands 的执行时间。
- `action_verification_time_seconds`：当前 high-level action 对应 verification commands 的执行时间。
- `action_total_time_seconds`：当前 high-level action 的 recovery commands + verification commands 总时间。
- `rollout_total_time_seconds`：从当前 candidate action 开始，严格真实 rollout 到终止条件或 `max_rollout_depth` 的累计恢复时间。planner 使用这个字段作为 candidate score。
- `baseline_restore_time_seconds`：`stop -> start -> run_attack -> replay selected history plans` 的耗时，只记录实验开销，不参与 candidate 选择。
- `wall_clock_time_seconds`：本次 candidate evaluation 实际墙钟时间，通常约等于 `baseline_restore_time_seconds + rollout_total_time_seconds` 加少量调度开销。

### `baseline_manager.py`

职责：

- 管理 candidate action 评估时的环境重建。
- 保证同一个时间节点的所有 candidate actions 都从相同 `baseline_t` 开始。
- 执行 `stop -> start -> run_attack -> replay selected history actions`。
- 在每次 candidate rollout 前调用 `state_verifier`，确认恢复出的状态等于 planner 当前状态。

第一版建议用串行方式，不并行跑多个 digital twin 实例。原因是当前 `llm_ir_dt_new` 的容器名、网络名和 IP 段都是固定的，并行多实例需要先参数化 `container_prefix`、`network_prefix` 和 IP 网段。

`baseline_t` 的定义：

```text
baseline_t = clean digital twin
           + run_attack.py
           + 已经被 planner 选中的历史 recovery command plans
```

也就是说，在第 `t` 个 planning step 评估任意 candidate action 前，都先重建同一个 `baseline_t`。

伪代码：

```python
def restore_baseline(history_plans):
    stop_digital_twin()
    start_digital_twin()
    run_attack()

    for plan in history_plans:
        recovery_executor.execute_plan(plan)

    restored_state = state_verifier.verify()
    return restored_state
```

### `plan_store.py`

职责：

- 保存每一步被最终选中的 high-level action 和对应 command plan。
- replay baseline 时直接复用已验证 command plan，而不是让 Codex 重新生成。
- 保存每次 candidate 评估结果，便于后续分析和复现实验。

不建议在 replay 历史动作时重新调用 Codex，因为同一个 high-level action 可能生成不同 bash commands，导致 `baseline_t` 不稳定。

建议 artifact 结构：

```text
artifacts/recovery_loop/
  runs/<run_id>/
    context.json
    selected_plans/
      step_001.json
      step_002.json
    candidate_evaluations/
      step_001/
        candidate_001.json
        candidate_002.json
        candidate_003.json
```

`selected_plans/step_001.json` 示例：

```json
{
  "step": 1,
  "server": "server_ssh",
  "server_ip": "10.0.2.11",
  "state_before": {
    "is_attack_contained": false,
    "is_knowledge_sufficient": false,
    "are_forensics_preserved": false,
    "is_eradicated": false,
    "is_hardened": false,
    "is_recovered": false
  },
  "high_level_action": "通过 gateway 阻断攻击主机访问 SSH server。",
  "high_level_action_explanation": "该动作可以先阻断攻击源到目标 SSH server 的连接，推进 containment 状态。",
  "raw_model_output": "{\"Action\": \"通过 gateway 阻断攻击主机访问 SSH server。\", \"Explanation\": \"该动作可以先阻断攻击源到目标 SSH server 的连接，推进 containment 状态。\"}",
  "command_plan": {
    "target_container": "gateway",
    "commands": [
      "iptables -I FORWARD -s 10.0.1.11 -d 10.0.2.11 -j DROP"
    ],
    "verification_commands": [
      "iptables -S"
    ]
  },
  "state_after": {
    "is_attack_contained": true,
    "is_knowledge_sufficient": false,
    "are_forensics_preserved": false,
    "is_eradicated": false,
    "is_hardened": false,
    "is_recovered": false
  },
  "rollout_total_time_seconds": 8.0,
  "baseline_restore_time_seconds": 60.0,
  "wall_clock_time_seconds": 68.0
}
```

### `state_verifier.py`

职责：

- 把命令执行证据转换成六个二值 recovery states。
- 支持 server-scoped 状态验证。

状态字段沿用当前项目中的六状态定义：

- `is_attack_contained`
- `is_knowledge_sufficient`
- `are_forensics_preserved`
- `is_eradicated`
- `is_hardened`
- `is_recovered`

在 digital twin 中，每个状态应该映射到具体可检查条件。例如：

- `is_attack_contained`：gateway 中存在对应 `iptables` 阻断规则，并且 attacker 无法连通目标服务器。
- `is_knowledge_sufficient`：已经收集目标主机、网络、服务、账号、IDS 告警等足够分析材料。
- `are_forensics_preserved`：关键证据已复制到带时间戳的 artifact 目录。
- `is_eradicated`：恶意文件、弱凭据、危险 CGI 入口、攻击者会话等已被移除。
- `is_hardened`：根因已修复，例如禁用 SSH 密码登录、禁止 root 登录、阻断 vulnerable CGI 访问。
- `is_recovered`：最终恢复态。目标服务健康检查通过，并且 containment、knowledge、forensics、eradication、hardening 都已完成。服务仍在运行只是必要条件，不足以单独判定 recovered。

可参考 `llm_ir_dt_new` 中已有的验证文档和脚本：

- `STATE_VERIFICATION_METHOD.md`
- `STATE_VERIFICATION_METHOD_CN.md`
- `verify_recovery_state.ps1`
- `verify_recovery_state211.ps1`

## Planner 集成方式

当前 planner 中的方法：

```python
IncidentResponsePlanner._estimate_recovery_time(logs, state, action)
```

现在是通过 LLM rollout 来估计恢复时间。新的设计中，它应该调用外部 executor：

```python
result = recovery_executor.evaluate_action(
    context=context,
    server=server,
    current_state=state,
    high_level_action=action,
)
return result.recovery_time_seconds
```

server-level planner loop 可以是：

```text
for each affected server:
    推断或加载该服务器当前六状态 recovery state
    while server state is not terminal:
        A100 上的本地微调模型生成多个 candidate high-level actions
        for each candidate action:
            baseline_manager 重建同一个 baseline_t
            Codex/OpenAI command_agent 生成 command plan
            command_safety 校验 command plan
            recovery_executor 在干净测试环境中执行 command plan
            state_verifier 计算 next state 和 recovery time
        选择 recovery time 最短且验证通过的 candidate
        把选中的 action 应用到 active environment
        plan_store 保存选中 action 的 command plan
        更新该服务器 state
```

## 重要实验约束

所有 candidate actions 必须从相同初始环境状态开始评估。否则恢复时间比较不公平。

错误做法：

```text
先在 live VM 上执行 candidate A。
再在已经被 A 修改过的同一 VM 上执行 candidate B。
然后比较 A 和 B 的恢复时间。
```

这是无效比较，因为 candidate B 的初始状态已经不是 candidate A 的初始状态。

推荐第一版采用 **串行重置 Docker digital twin + replay 历史动作**。对当前仓库来说，这是最现实的方案：

```text
active planning state = state_t
selected history plans = [best_action_1, ..., best_action_{t-1}]

评估 candidate a1:
  stop digital twin
  start clean digital twin
  run_attack.py
  replay selected history plans
  assert verified_state == state_t
  rollout a1
  save evaluation result
  discard environment

评估 candidate a2:
  stop digital twin
  start clean digital twin
  run_attack.py
  replay selected history plans
  assert verified_state == state_t
  rollout a2
  save evaluation result
  discard environment

评估 candidate a3:
  stop digital twin
  start clean digital twin
  run_attack.py
  replay selected history plans
  assert verified_state == state_t
  rollout a3
  save evaluation result
  discard environment

选择 best candidate:
  根据 success、state progress、rollout_total_time_seconds 选出最优 action
  再重建 baseline_t 或使用 active environment
  执行 best candidate
  保存 selected command plan
  更新 planner state
```

这样比较的是：

```text
baseline_t -> a1 rollout -> discard
baseline_t -> a2 rollout -> discard
baseline_t -> a3 rollout -> discard
```

而不是：

```text
baseline_t -> a1 rollout -> a2 rollout -> a3 rollout
```

后者是不公平的，因为 a2 和 a3 的初始状态已经被前面的 action 改变。

rollout 评估也应发生在 candidate 自己的临时环境中。例如评估 `a1` 时：

```text
restore baseline_t
execute a1
verify next_state
if next_state is not terminal:
    生成 rollout action b1
    execute b1
    verify next_state
    ...
until terminal or max_rollout_depth
record total recovery_time_seconds
discard environment
```

已确认：第一版采用严格真实 rollout。也就是说，评估某个 candidate action 时，不只真实执行第一步 candidate action，后续 rollout actions 也必须经过：

```text
high-level action
  -> Codex/OpenAI command_agent 生成 bash command plan
  -> command_safety 校验
  -> recovery_executor 在 digital twin 中真实执行
  -> state_verifier 真实验证 next state
  -> 累计真实执行和验证时间
```

因此，某个 candidate 的 `rollout_total_time_seconds` 表示从同一个 `baseline_t` 开始，沿着该 candidate 对应 rollout 路径真实执行到目标终止条件所花费的累计恢复时间，而不是模型估计时间。planner 使用 `rollout_total_time_seconds` 作为 candidate score。

`baseline_restore_time_seconds` 单独记录，但不参与 candidate 选择。原因是 reset/start/run_attack/replay history 是为了构造公平初始状态付出的实验开销，不是 recovery action 本身的恢复能力。

为控制第一版实验成本，建议先限制：

```text
num_candidates = 3
num_rollouts = 1
max_rollout_depth = 2 或 3
```

跑通后再逐步增加 `num_rollouts` 和 `max_rollout_depth`。

这种方式比纯 LLM rollout 慢，但恢复时间来自真实命令执行和真实状态验证。第一版先接受这个成本，等端到端闭环跑通后再考虑优化。

后续可选优化：

1. **Docker baseline 快照或 checkpoint**：理论上可以减少重建时间，但多容器网络、Snort 和 iptables 场景下稳定性需要验证。
2. **多 digital twin 实例并行评估**：需要先参数化容器前缀、网络前缀和 IP 网段。
3. **GCP VM snapshot/clone**：适合以后做宿主机级恢复动作评估，不建议第一版就使用。

## Codex 的参与边界

Codex 应该参与：

- command planner：把 high-level action 转成 command plan；
- command reviewer：审查命令是否合理、完整、危险；
- failure-analysis helper：当命令失败时，根据 stderr/stdout 和当前状态生成修正版计划。

Codex 不应该直接成为一个无限制远程 shell。

项目代码应该掌握：

- command validation；
- command execution；
- timing；
- state verification；
- artifact collection；
- environment reset；
- final action selection。

这样系统才可审计，也能避免命令生成模型直接变成不受限制的 VM 控制器。

## 最小实现计划

1. 第一版只针对 `server_ssh` / `10.0.2.11`。
2. 沿用 `planning_simulation_qwen_lora_DTserver.py` 的 high-level action 采样逻辑。
3. 增加 candidate action 解析：优先从模型输出 JSON 中提取 `"Action"` 和 `"Explanation"`。
4. 保存 `raw_model_output` 到 artifact，供调试、审计和复现实验使用。
5. 基于 `examples/predict_llm_ir_dt_new_initial_states_server.py` 增加 server-level context extraction。
6. 定义 server-scoped high-level action 的 JSON schema。
7. 新增 `command_agent.py`，从 high-level action 生成 command plan。
8. 新增 `command_safety.py`，实现严格 allowlist/denylist 校验。
9. 新增 `recovery_executor.py`，使用 `DockerManager.exec_run` 执行命令。
10. 新增 `baseline_manager.py`，实现 `stop -> start -> run_attack -> replay selected history plans`。
11. 新增 `plan_store.py`，保存 selected plans 和 candidate evaluation artifacts。
12. 新增 `state_verifier.py`，实现 digital twin 中的具体状态检查。
13. 修改或包装 `IncidentResponsePlanner._estimate_recovery_time()`，让它可以调用真实 `RecoveryExecutor`。
14. 在 `server_ssh` 上跑通端到端实验。
15. 扩展到 `server_samba`、`server_shellshock` 和正常 web servers。
16. Docker digital twin 闭环稳定后，再考虑扩大到 GCP VM 级别的恢复命令执行。

## 下一步实现前需要确认的问题

下面这些问题会影响代码结构。建议在写代码前先确认第一版边界。

1. **第一版是否只做 `server_ssh`？**
   已确认：第一版只做 `server_ssh`，因为 SSH brute force 的 containment、evidence、hardening、recovery 都比较容易验证。

2. **candidate action 的来源是否沿用 `planning_simulation_qwen_lora_DTserver.py`？**
   已确认：第一版沿用它的 high-level action 采样逻辑，并增加 JSON `"Action"` / `"Explanation"` 解析和 `raw_model_output` 保存。

3. **rollout 中后续 action 是否也调用 Codex 真实执行？**
   已确认：第一版采用严格真实 rollout。`candidate first action + rollout actions` 都必须生成 command plan、执行、验证、计时。恢复时间使用真实累计时间，不使用模型估计时间。为避免第一版成本过高，建议先限制 `max_rollout_depth=2` 或 `3`。

4. **恢复时间计量范围是什么？**
   已确认：planner 使用 `rollout_total_time_seconds` 作为 candidate score。该时间只包含 candidate rollout 内真实 recovery commands 和 verification commands 的累计时间。`reset/start/run_attack/replay baseline` 的耗时单独记录为 `baseline_restore_time_seconds`，不参与 candidate 选择。

5. **baseline replay 失败怎么办？**
   建议如果 replay selected history plans 后 `state_verifier` 得到的状态不等于 `state_t`，本次 candidate evaluation 直接标记为 invalid，不继续执行 candidate。

6. **Codex/OpenAI command generation 的接口形式是什么？**
   已确认：当前版本保留 mock/stub，并已支持 `OpenAICommandAgent` 和 `DeepSeekCommandAgent`。正式实验可用 `--command-agent deepseek` 接 DeepSeek V4 Pro，也可用 `--command-agent openai` 接 OpenAI Responses API；mock 只用于调试闭环和排查环境问题。

7. **命令安全边界是否只限制在 Docker 容器内？**
   建议第一版只允许 `DockerManager.exec_run(container, command)`，不允许直接在宿主 GCP VM 上执行恢复命令。

8. **状态验证是规则优先还是模型判断？**
   建议第一版用规则验证，尤其是 `server_ssh`：iptables、ping、auth.log、sshd_config、service health check。模型可以作为解释层，不作为最终 pass/fail 判定。

9. **artifact 保存目录是否固定为 `llm_ir_dt_new/artifacts/recovery_loop/`？**
   建议固定到 `llm_ir_dt_new/artifacts/recovery_loop/`，因为第一版执行环境在 `llm_ir_dt_new`。

## 第一阶段目标

第一阶段建议选择 `server_ssh`。

原因：

- 攻击路径清楚：SSH brute force 和弱口令。
- containment 容易通过 gateway `iptables` 验证。
- 证据收集简单，可以检查 `/var/log/auth.log`、`/etc/passwd`、`/home/admin`。
- hardening 可以表示为禁用 root login 或禁用 password authentication。
- recovery 可以通过 SSH/service health check 验证。

等 `server_ssh` 跑通后，再用相同结构扩展到 Samba 和 Shellshock。
