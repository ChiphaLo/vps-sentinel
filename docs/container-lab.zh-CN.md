# 轻量容器验证

先在 Linux 构建 release，再运行隔离实验：

```sh
cargo build --locked --release
sudo python3 tests/container_lab/run.py \
  --binary target/release/vps-sentinel --output /tmp/sentinel-lab-results
```

实验构建两个镜像：运行镜像只包含 Debian slim、CA 证书和 release 二进制；实验镜像额外安装 SSH、HTTP 日志服务及验证工具。这些测试工具不会进入运行镜像。实验使用 Docker internal 网络，不发布端口，不挂载宿主根目录或 Docker socket，不使用宿主 PID/network 或 privileged 模式。NET_ADMIN 仅用于实验容器自己的接口和防火墙。为测试只接受公网来源的封禁规则，脚本创建一对未分配地址的 veth，然后先把两端分别移入两个实验容器，再配置形似公网的测试 IP。这条连接仅存在于容器网络命名空间，不向真实公网地址发送请求，也不添加宿主公网地址或路由。

验证内容包括真实 SSH 密码失败、HTTP 敏感路径探测，以及假设容器内部已经取得 root 后的惰性 WebShell 文件、cron 持久化、SSH key 文件变化、额外 UID 0 用户、伪装矿工的 sleep 进程和 SUID/SGID、capability 变化。不会执行 WebShell、启动 cron 任务或进行真实挖矿。

主动响应只执行攻击源 IP 封禁。实验分别验证实际连接被拒、手动解封和 TTL 到期清理。产品不自动杀进程、删除后门或恢复账户；实验脚本先保存证据，再仅清理自己创建的文件、进程和账户修改，最后复扫验证。报告中明确区分产品封禁和实验脚本清理，不能把后者当成自动入侵修复能力。

FILE-005/FILE-006 在既有 FIM 路径上检测权限、uid/gid 和 Linux `security.capability` 状态变化。只读取一个有界 xattr，不调用外部 getcap、不增加依赖、不做全盘 SUID 扫描。capability 证据是原始属性的十六进制表示；未知或读取失败不视为“已移除”。规则只覆盖 `[file_integrity].paths` 所监控的文件，关键二进制需要按需加入路径。

旧基线可以兼容读取，但没有历史权限/capability 值时无法推断先前变化。升级后应在确认当前状态可信时重新建立基线，之后才能可靠比较这些元数据。报告中的短暂凭据读取和已结束的外连是覆盖缺口探针：没有 audit/eBPF 数据源时，轮询快照无法保证识别。实验不加载宿主内核探针，也不宣称具备 rootkit 清除能力。

每次扫描的 JSON、规则、响应结果、镜像大小、扫描时间、RSS 和实验清理结果保存到 `--output`。实验结束会删除它创建的容器、网络和镜像，并检查宿主防火墙恢复；现有业务容器不受影响。
