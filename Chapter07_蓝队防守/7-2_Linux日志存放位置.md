### Linux 日志存放位置

以下是一些重要日志文件及其作用：

- **/var/log/messages** 或 **/var/log/syslog**：记录系统级别的一般性消息，例如内核消息、系统服务启动/停止、硬件故障等
- **/var/log/secure** 或 **/var/log/auth.log**：记录与用户身份验证和安全相关的事件，例如登录尝试（成功或失败）、sudo 命令使用等
- **/var/log/boot.log**：记录系统启动过程中的日志
- **/var/log/dmesg**：记录内核环缓冲区中的消息，可以查看系统启动时硬件检测和驱动加载的信息
- **/var/log/lastlog**：记录每个用户最后一次登录的信息，可以通过 **lastlog** 命令查看
- **/var/log/wtmp** 和 **/var/log/btmp**：以二进制格式记录用户登录和注销的信息，可以使用 **who**、**w** 和 **last** 命令来查看
  - **wtmp**：记录所有登录和注销事件
  - **btmp**：记录所有失败的登录尝试
- **Web 服务器日志**：例如 Apache 或 Nginx 的日志通常在 **/var/log/httpd/** 或 **/var/log/nginx/** 目录下，包括访问日志（access.log）和错误日志（error.log）