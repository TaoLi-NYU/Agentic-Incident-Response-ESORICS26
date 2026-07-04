# 六状态恢复验证方法说明

本文档说明如何在 `llm_ir_dt_new` 数字孪生实验环境中，对恢复过程的六个状态位进行操作化验证，并将结果保存为可复查的日志、摘要和结构化 JSON 文件。

本文档对应的验证脚本为：

- [verify_recovery_state.ps1](D:/RA%20Project/AI%20Agent&Cybersecurity%20paper/llm_recovery/llm_ir_dt_new/verify_recovery_state.ps1)

执行恢复动作并保存执行日志的脚本为：

- [generated_recovery_plan_logged.ps1](D:/RA%20Project/AI%20Agent&Cybersecurity%20paper/llm_recovery/llm_ir_dt_new/generated_recovery_plan_logged.ps1)

## 1. 目的

本方法的目标不是证明系统达到了现实生产环境中的绝对安全状态，而是为数字孪生实验环境建立一套可重复、可记录、可解释的恢复状态判定机制。

该机制服务于以下研究问题：

- 微调后的模型生成的恢复动作是否可执行
- 执行这些动作后，系统是否在预定义的恢复状态上发生了正向变化
- 是否能够通过明确的主机检查、网络检查和日志检查，证明恢复状态已经满足

## 2. 六个状态位

本项目采用的数据集与论文框架，将恢复过程表示为六个布尔状态位：

- `is_attack_contained`
- `is_knowledge_sufficient`
- `are_forensics_preserved`
- `is_eradicated`
- `is_hardened`
- `is_recovered`

在实验中，每个状态位都需要被映射为可以实际检查的系统条件，而不能只停留在抽象语义层面。

## 3. 验证结果的保存方式

验证脚本执行后，会在以下目录生成结果：

- `artifacts/recovery_state_verification/`

生成三类文件：

- `verify_recovery_state_<timestamp>.log`
- `verify_recovery_state_<timestamp>.summary.txt`
- `verify_recovery_state_<timestamp>.json`

三类文件的作用如下：

- `.log`：保存每个状态位的检查过程、命令输出和详细证据
- `.summary.txt`：给出每个状态位的 `PASS` 或 `FAIL`
- `.json`：给出结构化验证结果，便于后续统计、绘图和论文引用

## 4. 状态位判定方法

### 4.1 `is_attack_contained`

定义：

- 攻击源已经被隔离，不能继续正常访问目标主机。

在本实验中的操作化判定：

- 检查 `gateway` 的 `iptables` 规则中，是否存在针对攻击源 `10.0.1.11` 的阻断规则
- 检查 `client` 是否已无法正常 `ping` 到 `server_ssh (10.0.2.11)`

判定理由：

- 如果网关已对攻击源加封锁规则，且攻击平台失去到目标网段的基础连通性，则可以认为攻击已被有效遏制

局限性：

- 这里只验证了实验中的主要攻击源与一条关键路径，不代表所有可能通信都已被严格阻断

### 4.2 `is_knowledge_sufficient`

定义：

- 已具备足够的主机和攻击上下文信息，能够重建攻击来源、影响目标和攻击路径。

在本实验中的操作化判定：

- `client` 上存在攻击工具与网络环境证据，如：
  - `password_list.txt`
  - `ip_addr.txt`
- `server_ssh` 上存在账户和主机上下文证据，如：
  - `passwd.txt`
  - `home_admin.txt`
- `server_shellshock` 上存在 HTTP 利用上下文证据，如：
  - `apache_access.log`
  - `cgi_file.sh`

判定理由：

- 这些证据能够帮助分析者回答以下问题：
  - 攻击从哪里发起
  - 使用了什么凭据和工具
  - 哪些主机和服务被访问
  - 具体利用了哪类服务弱点

局限性：

- 这里验证的是“已有足够材料可分析”，而不是“分析工作已经全部完成”

### 4.3 `are_forensics_preserved`

定义：

- 关键证据已经从易失的运行态位置复制到专门的证据目录中，便于后续复查。

在本实验中的操作化判定：

- `gateway` 上保存了：
  - `snort.alert`
  - `iptables.rules`
- `server_ssh` 上保存了：
  - `auth.log`
  - `passwd.txt`
- `server_samba` 上保存了：
  - `samba_logs.txt`
  - `share.tar.gz`
- `server_shellshock` 上保存了：
  - `apache_access.log`
  - `apache_error.log`

判定理由：

- 这些文件覆盖了网络告警、主机登录、文件共享访问和 Web 利用痕迹，是当前实验场景下最关键的取证材料

局限性：

- 该方法不涉及磁盘镜像、内存镜像或证据链条控制，因此属于实验型证据保全，不是法证级采集

### 4.4 `is_eradicated`

定义：

- 已观测到的攻击工具和落地工件已经从系统中移除。

在本实验中的操作化判定：

- `client` 中不再存在以下攻击相关进程：
  - `hydra`
  - `nmap`
  - `smbclient`
  - `sshpass`
- `server_samba` 中由攻击过程上传的 `evil_payload.txt` 已不存在

判定理由：

- 如果攻击平台上不再运行已知攻击工具，且靶机上不存在明显落地工件，可以认为当前实验中观测到的主要攻击痕迹已经被清除

局限性：

- 这并不等于严格意义上的“完全根除”，因为实验没有做镜像级重建或深层后门扫描

### 4.5 `is_hardened`

定义：

- 系统配置已被收紧，使原攻击路径难以再次成立。

在本实验中的操作化判定：

- `server_ssh` 配置被修改为：
  - `PermitRootLogin no`
  - `PasswordAuthentication no`
  - `MaxAuthTries 3`
- `server_samba` 配置被修改为：
  - `guest ok = no`
  - `read only = yes`
- `server_shellshock` 的 CGI 文件已不可执行
- `gateway` 已存在针对以下风险的过滤规则：
  - 面向 `10.0.1.11` 的 SSH 暴力尝试控制
  - 到 `server_samba` 的 SMB 访问限制
  - 到 `server_shellshock` 的 Shellshock 特征过滤

判定理由：

- 该状态位强调的不是“系统已恢复运行”，而是“系统已对已知攻击路径进行约束”

局限性：

- 当前加固是面向实验场景的最小化加固，不代表已经达到通用生产安全基线

### 4.6 `is_recovered`

定义：

- 核心服务已继续运行，并且恢复动作没有破坏实验环境的基本可用性。

在本实验中的操作化判定：

- `gateway` 仍可访问两台正常 Web 主机：
  - `10.0.2.14`
  - `10.0.2.15`
- 关键服务进程仍在运行：
  - `server_ssh` 上的 `sshd`
  - `server_samba` 上的 `smbd`
  - `server_shellshock` 上的 `apache`
  - `server_web1` 上的 `nginx`
  - `server_web2` 上的 `nginx`

判定理由：

- 这证明恢复措施并未导致实验环境整体失效，同时基础服务能力仍在

局限性：

- 这里只做进程和可达性层面的恢复验证，不等同于完整业务级功能测试

## 5. 为什么要同时保存日志、摘要和 JSON

三种输出形式分别面向不同用途：

- 日志适合人工审计和答辩展示
- 摘要适合快速判断六个状态位是否通过
- JSON 适合后续自动统计和论文图表生成

这种设计可以提高实验可追溯性，并降低“只看结论、不看证据”的风险。

## 6. 这套方法能证明什么

它可以证明：

- 恢复动作执行后，系统满足了一组明确、可复查、与六状态位对应的实验条件
- 每个状态位是否通过，都有具体命令输出作为证据
- 结果已被落盘保存，不依赖人工口头判断

## 7. 这套方法不能证明什么

它不能证明：

- 系统在现实生产环境中一定完全恢复
- 系统已经达到法证级或工业级恢复标准
- 没有任何隐藏后门或未知持久化机制残留

因此，本方法更准确的定位是：

- 面向数字孪生恢复实验的状态验证方法

而不是：

- 面向生产系统的最终恢复认证机制

## 8. 建议的论文表述

如果要在论文中简要描述本方法，可以采用如下表述：

> 为评估微调模型生成的恢复动作是否能够推动系统进入目标恢复状态，我们将恢复过程形式化为六个布尔状态位，并为每个状态位设计了可操作的系统级验证条件。验证脚本通过在数字孪生容器中执行网络、配置、进程与证据文件检查，将结果保存为详细日志、摘要文件和结构化 JSON，从而形成可复查的恢复状态证据链。

如果要强调边界，可以补充：

> 该方法服务于实验环境中的恢复状态评估，其目标是建立可重复、可解释的研究验证流程，而非提供生产级法证认证。

## 9. 配套执行顺序

建议按以下顺序运行：

1. 执行模型生成的恢复动作：

```powershell
powershell -ExecutionPolicy Bypass -File .\generated_recovery_plan_logged.ps1
```

2. 验证六个状态位：

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_recovery_state.ps1
```

3. 查看结果：

- `artifacts/generated_recovery_logs/`
- `artifacts/recovery_state_verification/`

## 10. 结论

本方法将抽象的恢复状态定义转换为具体可执行的系统检查，并通过文件落盘保存验证结果，从而使“模型是否真的让系统恢复”这个问题可以被实验性回答、复核和引用。
