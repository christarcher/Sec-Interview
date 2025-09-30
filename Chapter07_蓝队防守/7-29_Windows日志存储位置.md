### Windows 日志存储位置

主要的日志类别及其文件如下：

- **应用程序日志 (Application)**：
  - **文件路径**：`%SystemRoot%\System32\Winevt\Logs\Application.evtx`
  - **内容**：记录由应用程序产生的事件，例如程序启动、停止、崩溃或错误信息
- **安全日志 (Security)**：
  - **文件路径**：`%SystemRoot%\System32\Winevt\Logs\Security.evtx`
  - **内容**：记录与安全相关的事件，例如用户登录/注销、权限更改、文件访问等。这对于应急响应和取证分析非常重要
  - **注意**：安全日志默认是关闭许多详细审计功能的，需要通过组策略（Group Policy）来启用更详细的审计策略
- **系统日志 (System)**：
  - **文件路径**：`%SystemRoot%\System32\Winevt\Logs\System.evtx`
  - **内容**：记录由 Windows 操作系统组件产生的事件，例如驱动程序加载失败、硬件错误、服务启动/停止等
- **Setup 日志 (Setup)**：
  - **文件路径**：`%SystemRoot%\System32\Winevt\Logs\Setup.evtx`
  - **内容**：记录 Windows 安装、升级或服务包安装过程中的事件