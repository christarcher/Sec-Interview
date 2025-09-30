### Windows 和 Linux 利用 REDIS 的区别

**1. 权限与用户**

- **Linux**: Redis 服务通常以低权限用户（如 `redis` 或 `nobody`）运行。这意味着即使你通过 Redis 成功写入了文件，比如写入一个 SSH 公钥到 `~/.ssh/authorized_keys`，你所能控制的也只是该低权限用户。要提升权限，你还需要找到另一个本地提权漏洞，这通常需要更多的步骤
- **Windows**: 在 Windows 上，Redis 常常以 `SYSTEM` 或其他管理员权限运行，尤其是在一些不规范的部署中。如果能通过 Redis 成功写入文件，例如写入一个 WebShell 到网站目录或创建一个启动项，你所获得的权限可能直接就是 `SYSTEM` 级别。这使得 Windows 上的利用变得更简单粗暴，危害也更大

**2. 利用方式**

- **Linux**:
  - **写 SSH 公钥**: 这是最经典的利用方式。通过 `config set dir /root/.ssh/` 和 `config set dbfilename authorized_keys`，然后用 `set` 命令写入公钥，最后用 SSH 连接。这需要知道目标系统的用户家目录，通常是 `root` 或 `redis` 用户
  - **写 Crontab**: 利用 Redis 写入定时任务，反弹 Shell。`config set dir /var/spool/cron/` 和 `config set dbfilename root`，然后写入反弹 Shell 的命令。这种方式可以获得稳定的 Shell，但需要 Redis 有足够的权限写入该目录
  - **写 WebShell**: 写入 PHP、JSP 等 WebShell 到网站目录，通常需要 Web 服务器和 Redis 运行在同一台机器上，并且 Redis 有写入 Web 目录的权限
- **Windows**:
  - **写 WebShell**: 写入 WebShell 到 `wwwroot` 或其他网站目录。这是最常见的利用方式，因为 Redis 经常与 Web 服务部署在同一台机器上
  - **写入启动项/服务**: 由于权限通常较高，可以直接写入 `.bat` 或 `.exe` 文件到启动目录或创建新的服务，实现权限维持和持久化
  - **DLL 劫持**: 高权限下的一个高级利用方式，将恶意的 DLL 文件写入到某个高权限程序会加载的路径，实现代码执行

**3. 环境与工具链**

- **Linux**:
  - **环境依赖**: Linux 环境下，渗透测试人员需要熟悉 Linux 文件系统路径、Cron 任务机制和各种 Shell 类型（Bash, Zsh）
  - **工具**: `redis-cli` 是最直接的交互工具。远程连接时，可以利用 `netcat` 或 `socat` 等工具来处理端口转发
  - **持久化**: Cron 任务、SSH 公钥都是很好的持久化手段
- **Windows**:
  - **环境依赖**: 熟悉 Windows 文件系统路径（如 `C:\Windows\System32`）、服务管理（`services.msc`）和启动项（`startup` 文件夹）
  - **工具**: `redis-cli` 同样适用。但后续的利用，如上传 WebShell，可能需要依赖更多的工具或脚本来执行
  - **持久化**: 写入服务、注册表键值、计划任务都是常见的持久化手段

| 特性     | Windows 利用                   | Linux 利用                           |
| -------- | ------------------------------ | ------------------------------------ |
| 权限     | 通常更高，甚至可达 SYSTEM      | 通常较低，为 redis 或 nobody         |
| 利用方式 | 写入 WebShell、启动项、服务等  | 写入 SSH 公钥、Crontab、WebShell     |
| 持久化   | 写入服务、计划任务、启动项     | 写入 Crontab、SSH 公钥               |
| 成功率   | 如果权限高，成功率高，后果严重 | 需要找到合适的写入路径，可能需要提权 |
| 主要区别 | 高权限直接执行命令，易于利用   | 低权限，需要提权，利用方式更依赖环境 |