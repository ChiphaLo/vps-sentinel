# 安全审查报告 - 2026-10-03

审查对象：ChiphaLo/vps-sentinel 的 main 分支，提交
[48ffa10](https://github.com/ChiphaLo/vps-sentinel/commit/48ffa107cb2562207b82bfa737d76875cf6d36fd)
（简体中文首页发布后的代码）。

状态：本次仅审查和记录，下列问题均未修复。仓库代码在该提交上没有改动；本地复核产生的原始证据保留在审查工作目录，本报告只记录方法、证据和边界。

## 总体结论

- 发现 6 个高优先级问题、4 个中优先级问题，以及 6 类入侵监测盲区。
- 风险集中在面板节点隔离、本地凭据文件权限、特殊文件阻塞、Web 文件覆盖、eBPF 数据通路和 Docker 网络封禁。
- 现有 14 项 Worker 测试全部通过；新增的双节点隔离用例稳定复现失败，说明测试覆盖没有包含跨节点覆盖风险。
- Rust 工作区测试和 hyvps 攻击测试未在本次审查中执行。hyvps 当前提供的 SSH 主机密钥与本地记录不一致，未覆盖校验，也未继续远程验证。

## 高优先级

### R1 配置备份与安装临时文件可能泄露凭据

- 位置：[config.rs](../crates/sentinel-cli/src/commands/config.rs#L1054)、install.sh 的 set_toml_value。
- 影响：配置迁移、默认值同步、规范化和白名单编辑会复制完整配置，备份没有显式限制为 0600；安装脚本的 set_toml_value 也会先用普通权限替换配置，再执行 chmod 0600。
- 证据：用安装脚本原函数在惰性密钥的临时配置文件上复现 0600 到 0644 的变化，内容仍包含该测试密钥。Rust 备份路径为源码确认，未运行 CLI 复现。
- 建议：备份和临时文件使用 create_new 与 0600 创建，拒绝软链接，采用同目录原子替换，并在替换后保持安全权限。

### R2 一个已入侵节点可以覆盖其他节点的告警或事件

- 位置：[worker.js](../panel/cloudflare/worker.js#L378)、crates/sentinel-panel/src/repository.rs 的 upsert。
- 影响：面板只验证上报节点身份，findings 和 incidents 使用客户端提供的全局主键。掌握其他节点记录 ID 的攻击者，仅凭自己的节点密钥就能覆盖对方记录。自建 Rust 面板使用 ON CONFLICT(id) 更新，保留受害节点归属但污染其证据。
- 证据：使用实际 Worker 和内存 SQLite D1 适配器，两个节点使用不同的独立密钥且关闭共享密钥。两次上报均返回 200，节点 A 的记录被节点 B 替换。
- 建议：在服务端按已验证节点命名空间化记录 ID，或改为 node_id 与 local_id 复合主键，并限制所有 upsert 只能更新本节点记录。

### R3 特殊文件可以让扫描无限阻塞

- 位置：[fs.rs](../crates/sentinel-agent/src/utils/fs.rs#L36)。
- 影响：日志读取和哈希函数没有拒绝 FIFO 或设备文件。FIM 会跟随显式软链接，SSH 自动发现会扫描 /home/*/.ssh/authorized_keys。低权限用户可以把可写 key 路径链接到没有写端的 FIFO，使 root 守护程序阻塞在 open；采集器串行运行，没有可中断的扫描时限。
- 证据：源码路径确认；未执行 Rust FIFO 运行时测试。
- 建议：打开后检查 fstat，只读取普通文件，使用非阻塞打开和有限读取，单独记录软链接属性；阻塞系统调用需要隔离执行，单纯异步超时无法中断。

### R4 默认 WebShell 文件检测没有接入 Web 根目录

- 位置：[file_integrity.rs](../crates/sentinel-agent/src/collectors/file_integrity.rs#L30)。
- 影响：FIM 只扫描 file_integrity.paths 和 SSH key 路径，默认路径不包含 web.web_roots。新上传到 /var/www 等目录的 WebShell 默认不会产生 FILE-002 或 FILE-003 所需的文件快照。自定义 FIM 路径可以缓解，但默认安装没有该覆盖。
- 证据：默认配置与 Rust 默认路径、采集器调用链源码确认。
- 建议：提供明确启用的 Web 文件监控配置并显示实际覆盖；采用有上限的增量检查，避免无界全盘扫描。

### R5 内置 eBPF 文件事件不能触发 FILE-004

- 位置：[file_rules.rs](../crates/sentinel-agent/src/detectors/file_rules.rs#L206)、crates/sentinel-agent/src/runtime_probe.rs 的文件探针。
- 影响：内置探针输出 file_write、file_rename、file_unlink，但不输出 operation；bridge 把类型统一成 file_activity，只从 op 或 action 补充 operation。FILE-004 对空 operation 必然返回 None。即使启用文件探针，短暂修改敏感文件后恢复仍可能漏报，O_RDWR 也没有被 openat 过滤条件捕获。
- 证据：探针、bridge 和 detector 的源码断言及标志位计算；未运行 bpftrace。
- 建议：由 source_kind 生成规范 operation，补齐打开标志、rename 目标和相对路径上下文，并用真实探针格式做端到端回归。

### R6 INPUT 封禁不能覆盖 Docker 发布端口

- 位置：[active_response.rs](../crates/sentinel-agent/src/active_response.rs#L1683)。
- 影响：iptables 只向 INPUT 写规则，nftables 也只创建 input hook。Docker bridge 的发布端口通常经过 FORWARD 或 DOCKER-USER，封禁集合可能写入成功并显示 blocked，但容器攻击流量仍可到达。此前容器自身 INPUT 的成功测试不能证明宿主发布端口受到保护。
- 证据：源码确认，并用 Docker 官方防火墙路径文档核对；本次没有重做宿主网络实验。
- 建议：区分主机输入、Docker 转发和反代应用封禁；在适当的 Docker 用户链或 nft forward hook 应用，并验证实际入口阻断。

## 中优先级

### R7 eBPF JSONL 部分写入导致事件丢失

- 位置：[ebpf_bridge.rs](../crates/sentinel-agent/src/collectors/ebpf_bridge.rs#L75)。
- 影响：读取器在确认完整行之前把 offset 推进到文件长度。扫描读到尚未完成的 JSON 行时会丢弃它，下一次只读剩余片段，无法恢复。超过 tail 上限时也会跳过旧数据但不产生数据源降级事件。
- 建议：只提交完整换行记录的偏移，保留部分行，按 inode 识别轮转，为队列溢出计数并告警。

### R8 探针字符串没有做 JSON 转义

- 位置：[runtime_probe.rs](../crates/sentinel-agent/src/runtime_probe.rs#L257)。
- 影响：printf 把进程可影响的 comm、exe、path 直接插入 JSON 引号；引号、反斜线或换行会生成非法 JSON 并被 bridge 静默丢弃。
- 建议：使用能可靠转义的输出协议或 bpftrace JSON 支持，对解析失败计数告警，并测试特殊字符和截断路径。

### R9 持久化采集的实际读取没有大小限制

- 位置：[persistence.rs](../crates/sentinel-agent/src/collectors/persistence.rs#L82)。
- 影响：哈希限制为 1 MiB 后，仍然用 read_to_string 读取整个文件。普通用户可以增大受监控的 ~/.profile 或 ~/.bashrc，导致守护程序大量分配内存；全局 raw event 预算在采集完成后才执行，不能限制这个阶段。
- 建议：对读取、路径数量、目录枚举和单次采集时间设置硬上限，超限保留元信息并报告未知覆盖。

### R10 首次扫描或污染基线中的非 root UID 0 账户不告警

- 位置：[user_rules.rs](../crates/sentinel-agent/src/detectors/user_rules.rs#L53)。
- 影响：USER-002 只消费用户新增或 UID 漂移事件，不检查 user_account 快照。没有基线时不产生 diff，安装默认先创建基线再扫描；安装前已存在的非 root UID 0 账户会被基线接受，后续稳定快照不会告警。
- 建议：对不依赖基线的危险状态直接检查，例如非 root UID 0；首次建立基线前展示风险并记录信任来源。

## 入侵监测缺项

| 领域 | 缺项 | 轻量改进方向 |
| --- | --- | --- |
| 凭据窃取 | 只检查审计命令字符串，未关联 SYSCALL 和 PATH 实际读访问；应用直接访问文件、环境变量和凭据缓存可能漏报。 | 对少量敏感路径配置审计读规则，关联记录序号、结果、UID 和进程身份。 |
| 短暂 C2 与外传 | 内置探针没有 connect、sendto、DNS、argv 和 ppid；轮询难以捕获短暂外连和低慢速外传。 | 可选采集新建外连和 DNS 异常，限定采样和存储预算，先报警不自动封禁。 |
| 反代客户端封禁 | Cloudflare 后的源 IP 是边缘地址；提取真实客户端 IP 后在源站 INPUT 封禁，通常不改变代理到源站的连通性。 | 在受信反代或应用入口执行策略，区分本地记录和实际入口阻断。 |
| rootkit 与程序完整性 | 只检查 ld.so.preload，没有内核隐藏对象、模块基线或程序包内容核验；进程哈希不是发行版可信哈希。 | 按需验证关键二进制包内容和模块状态，不宣称完整 rootkit 检测。 |
| 采集失明与自身保护 | 缺失 audit 或 eBPF 文件时常返回空事件，Docker 命令失败也可能表现为正常；默认不监控自身 binary、config 和 db。 | 上报每个采集源的健康、覆盖、丢失量和成功时间；独立面板告警缺失心跳。 |
| 业务和容器行为 | 重点是 SSH、Web 路径和 Docker 配置，缺少业务登录、数据库凭据、容器 exec、短命容器和横向移动审计。 | 按实际部署接入高价值认证日志和 Docker 事件，限制可读范围和速率。 |

## 依赖公告数据

- 查询 Cargo.lock 中 280 个 registry 包：只匹配到 RUSTSEC-2023-0071，即 RSA 0.9.10 的时间侧信道公告，CVSS 5.9，暂无修复版本。锁文件命中不代表该应用可达，需要结合 SQLx MySQL 路径单独评估。
- 查询 panel/ui 的 61 个 npm 包：没有匹配公告。
- 这不是完整代码审计结论，也不能排除代码自身漏洞。

## 复现与边界

- 原有 Worker 测试：14 项通过，0 失败；范围是实际 Worker 加 Node SQLite D1 适配器，不是 Cloudflare 部署测试。
- 新增跨节点隔离用例：可稳定复现 R2。
- 配置权限：用安装脚本原函数复现 R1 的 0600 到 0644 变化。
- 数据通路检查：R4、R5 由源码断言和标志位计算确认。
- 未执行：编译后的 Rust 复现、完整工作区测试、hyvps 运行时攻击测试、bpftrace 实测。
- hyvps SSH 主机密钥与本地记录不一致，已停止连接，没有覆盖校验。

原始 JSON 和工作日志保留在本地审查工作目录，不随本报告提交。
