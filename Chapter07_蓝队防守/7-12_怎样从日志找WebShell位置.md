### 怎样从日志找 WebShell 位置

**第一步：排查 Web 服务器访问日志（access.log）**

WebShell 需要通过 HTTP 请求来执行命令，因此会在 Web 服务器的访问日志中留下痕迹。这是定位 WebShell 位置最直接的方法

- **异常请求状态码**：一个成功的 WebShell 文件通常会被频繁访问，并返回 `200` 状态码。而正常的网站文件，尤其是那些不应该被直接访问的脚本文件，如果返回了 `200`，就很可疑
- **异常请求路径**：WebShell 的路径通常很奇怪，不符合正常的业务规则。例如：
  - **深度目录**：`www.example.com/images/uploads/2023/shell.php`
  - **随机文件名**：`www.example.com/1a2b3c4d.jsp`
  - **伪装文件名**：`www.example.com/test.jpg.php`
- **异常请求参数**：WebShell 的请求参数通常会包含一些命令执行的关键字，例如 `?cmd=...`、`?exec=...` 或 `?id=...`
- **异常 User-Agent**：攻击者可能使用特定的工具或脚本来访问 WebShell，其 User-Agent 字段可能不正常

**第二步：排查 Web 服务器错误日志（error.log）**

WebShell 可能会在运行中产生错误，这些错误通常会被记录在错误日志中

- **PHP 错误**：如果一个 PHP 文件尝试执行一个它没有权限执行的操作，或者语法错误，错误日志中会记录下该文件的完整路径。例如：`PHP Warning: file_put_contents(/var/www/html/malicious_file.php): failed to open stream: Permission denied in /var/www/html/upload/shell.php on line 10`
- **Java 异常**：对于 Java Web 应用，WebShell 可能会抛出异常，错误日志会显示异常发生的类名和路径

通过这些错误信息，可以快速定位到可疑文件的具体位置