### 为什么 MMSQL 存储过程可以执行命令

**1. `xp_cmdshell` 存储过程**

这是 MSSQL 中最著名，也是最危险的命令执行功能

**原理**

`xp_cmdshell` 是一个扩展存储过程（e**x**tended **p**rocedure）。它允许你在 SQL Server 内部执行操作系统的 **`cmd.exe`** 命令

当你执行 `EXEC xp_cmdshell 'dir c:\'` 时，SQL Server 会：

1. 启动一个 `cmd.exe` 进程
2. 将你的命令作为参数传递给 `cmd.exe`
3. 将命令的输出结果以行的形式返回到 SQL Server 的结果集中

**使用条件**

默认情况下，从 SQL Server 2005 开始，`xp_cmdshell` 处于**禁用状态**。要成功利用它，需要满足以下两个条件：

- **权限**：你必须拥有 **`sysadmin`** 服务器角色或**`CONTROL SERVER`**权限，这是因为 `xp_cmdshell` 默认只授予这些高权限用户

- **启用配置**：`xp_cmdshell` 必须通过以下 SQL 命令手动启用：

  ```sql
  sp_configure 'show advanced options', 1;
  RECONFIGURE;
  sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;
  ```

在渗透测试中，如果成功通过 SQL 注入或其他方式获得了高权限，你就可以执行这些命令来启用 `xp_cmdshell`，然后执行任意系统命令

**2. 其他相关的危险存储过程**

除了 `xp_cmdshell`，MSSQL 还有其他一些可以执行命令或辅助命令执行的存储过程，但它们不像 `xp_cmdshell` 那样直接

**`sp_addextendedproc`**

- **原理**：这个存储过程允许你将一个外部 DLL 文件注册为 SQL Server 的扩展存储过程
- **用途**：如果攻击者能上传一个恶意的 DLL 文件到服务器，就可以利用 `sp_addextendedproc` 将其注册为一个新的扩展存储过程，然后通过执行这个过程来执行恶意代码，从而绕过 `xp_cmdshell` 的禁用限制

**CLR 集成（SQL CLR）**

- **原理**：SQL Server 允许你使用 .NET 语言（如 C#）编写存储过程、函数、触发器等。这些代码可以调用 .NET 框架中的类库，包括那些可以执行系统命令的类，如 `System.Diagnostics.Process`
- **用途**：攻击者可以编写一个恶意的 C# 代码，将其编译成 DLL，然后加载到 SQL Server 中。这是一种更隐蔽、更强大的命令执行方法，因为它不依赖于 `xp_cmdshell`