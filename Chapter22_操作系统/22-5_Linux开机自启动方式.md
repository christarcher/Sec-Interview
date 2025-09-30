### Linux 开机自启动方式

**系统级别的自启动方式**

这些是系统在引导过程中自动执行的脚本或服务，通常用于启动核心服务和守护进程

**1. Systemd**

Systemd 是现代 Linux 发行版（如 Ubuntu 16.04+、CentOS 7+、Debian 8+）中最主流的启动管理器。它使用 **`.service`** 单元文件来定义服务，这些文件通常存放在以下目录：

- `/etc/systemd/system/`：管理员创建或修改的服务文件
- `/usr/lib/systemd/system/`：软件包安装的服务文件，不建议直接修改

恶意程序可能会在这些目录中创建或修改 `.service` 文件，将自己伪装成一个合法的服务

**如何检查：**

- `systemctl list-unit-files --type=service`：列出所有服务的单元文件
- `systemctl status <service_name>`：检查特定服务的状态
- `systemctl cat <service_name>`：查看服务文件的具体内容，包括执行命令

**2. Init 脚本**

在较旧的 Linux 发行版中（如 CentOS 6、Ubuntu 14.04），系统使用 Init 脚本来管理启动

- **SysVinit**：脚本存放在 `/etc/init.d/` 目录，通过 `rcX.d` 目录（X代表运行级别）的软链接来控制服务的启动顺序
- **Upstart**：配置文件存放在 `/etc/init/` 目录

恶意程序可能会在 `/etc/init.d/` 中添加新脚本，或在 `/etc/rcX.d/` 中创建软链接，从而在系统启动时被执行

**如何检查：**

- `ls -l /etc/init.d/`：查看所有 Init 脚本
- `ls -l /etc/rc?.d/`：查看不同运行级别下的软链接

**用户级别的自启动方式**

这些方式通常只在特定用户登录后才会被执行，常用于启动桌面环境下的应用程序

**1. Cron 定时任务**

Cron 用于在指定的时间自动执行任务，也可以被配置为在系统启动时执行

- `/etc/crontab`：系统级别的 Cron 文件，可用于设置在系统启动时执行的脚本（使用 `@reboot` 关键字）
- `/etc/cron.d/`：存放独立的系统级 Cron 文件
- `/var/spool/cron/crontabs/<username>`：用户级别的 Cron 文件

恶意程序可能会利用 `@reboot` 字段，将自己添加到这些文件中，从而实现开机自启动

**如何检查：**

- `cat /etc/crontab`：查看系统 Cron 文件
- `ls -l /etc/cron.d/`：查看独立 Cron 文件
- `crontab -l`：查看当前用户的 Cron 任务
- `crontab -l -u <username>`：查看特定用户的 Cron 任务。

**2. 用户配置文件**

许多 Shell 和桌面环境都有自己的启动文件

- `~/.bashrc`、`~/.bash_profile`、`~/.profile`：这些文件在用户登录时会被 Shell 加载，恶意代码可以被注入其中
- `~/.config/autostart/`：桌面环境（如 GNOME、KDE）下的自启动目录。这个目录下的 `.desktop` 文件可以指定一个程序在用户登录后自动运行

**如何检查：**

- `cat ~/.bashrc`、`~/.bash_profile` 等：检查可疑命令
- `ls -l ~/.config/autostart/`：查看可疑的 `.desktop` 文件

**其他隐蔽的自启动方式**

除了上述常见方式，恶意程序还可能采用更隐蔽的手段。

**1. SUID/SGID 文件**

虽然不是直接的自启动方式，但拥有 SUID 或 SGID 权限的程序可以在不询问用户密码的情况下以高权限运行，这对于持久化攻击非常有用。攻击者可以利用这些程序在系统启动后被调用时，执行自己的恶意代码

**如何检查：**

- `find / -type f -perm /4000 2>/dev/null`：查找所有 SUID 文件。
- `find / -type f -perm /2000 2>/dev/null`：查找所有 SGID 文件

**2. SSH 密钥**

攻击者可以修改 `~/.ssh/authorized_keys` 文件，添加自己的公钥，从而在无需密码的情况下远程登录。虽然不是开机自启动，但它能让攻击者在系统重启后仍能获得持续访问权限

**如何检查：**

- `cat ~/.ssh/authorized_keys`：检查是否存在陌生的公钥

**3. 动态链接库**

`LD_PRELOAD` 环境变量可以让攻击者在程序启动时预先加载一个恶意动态链接库（`.so` 文件），从而劫持合法程序的函数调用，实现代码注入。如果将 `LD_PRELOAD` 变量写入全局配置文件（如 `/etc/profile`），则会对所有用户生效

**如何检查：**

- `cat /etc/profile`、`~/.bashrc` 等：检查 `LD_PRELOAD` 环境变量是否被设置