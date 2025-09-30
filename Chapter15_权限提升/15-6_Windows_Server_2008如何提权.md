### 现在有一台 Windows Server 2008 如何提权

**第一步：信息收集**

在尝试任何攻击之前，必须先了解你所处的环境。这一步是成功的关键，可以帮助你快速定位可行的提权路径

1. **检查当前权限：**
   - `whoami /priv`：查看当前账户拥有的特权。某些特权（如 `SeDebugPrivilege`）可以直接用于窃取哈希或执行其他高权限操作
2. **系统信息和补丁：**
   - `systeminfo`：查看系统版本、架构和安装的补丁列表。这对于判断系统是否对已知的内核漏洞免疫至关重要
   - `wmic qfe get Caption,Description,HotFixID,InstalledOn`：更详细地查看已安装的补丁
3. **服务和进程：**
   - `tasklist /svc`：查看哪些服务正在运行，以及它们以什么权限运行
   - `Get-Service` (PowerShell)：查找以 `LocalSystem` 或其他高权限账户运行的服务
4. **目录和文件权限：**
   - `icacls C:\`：检查关键目录（如 `C:\Program Files`）的写入权限。如果低权限用户可以写入，则可能存在 **DLL 劫持**或 **可执行文件替换**的漏洞
5. **注册表权限：**
   - `reg query HKLM`：检查注册表键的权限，尤其是那些与服务或自动运行程序相关的键
6. **计划任务：**
   - `schtasks /query`：查看是否有以高权限账户运行的计划任务，且低权限用户可以修改其执行文件或参数

**第二步：利用常见的配置错误（首选）**

这些方法通常不需要复杂的漏洞利用，成功率高且隐蔽性强

**1. 不安全的服务的可执行文件路径**

如果一个服务的路径没有用引号括起来，并且路径中包含空格，Windows 会尝试从每个空格分隔的目录中寻找可执行文件

- **示例：** 服务路径为 `C:\Program Files\My Service\service.exe`
- **Windows 搜索顺序：**
  1. `C:\Program.exe`
  2. `C:\Program Files\My.exe`
  3. `C:\Program Files\My Service\service.exe`
- **利用方式：** 如果低权限用户对 `C:\Program Files` 或 `C:\` 目录有写入权限，就可以在该目录中创建一个恶意的可执行文件（如 `My.exe`）。当服务重启时，它会首先执行这个恶意程序，从而获得服务的权限

**2. 服务配置权限不当**

如果低权限用户可以修改某个高权限服务的配置，例如更改其二进制文件路径，就可以实现提权

- **检查方法：** `sc qc [ServiceName]`
- **利用方式：** 使用 `sc config` 命令修改服务的 `binpath` 指向你的恶意程序，然后重启服务

**3. 注册表键 AlwaysInstallElevated**

如果以下两个注册表键都为 `1`，那么任何用户都可以以 **System** 权限运行 MSI 安装文件

- `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- **利用方式：** 创建一个恶意的 MSI 安装包（可以使用 `msfvenom` 生成），然后双击运行，它会以 `System` 权限执行你的代码

**第三步：利用内核漏洞**

如果配置错误的方法都不可行，可以尝试利用 Windows Server 2008 上已知的内核漏洞

- **MS11-046 (AFD.sys):** 这是一个非常经典的漏洞，允许低权限用户提升至 `SYSTEM` 权限
- **MS14-066 (sctp.sys):** 另一个著名的权限提升漏洞，通常被用于获得 `SYSTEM` 权限
- **MS15-051 (win32k.sys):** 同样是一个广泛使用的权限提升漏洞

**重要提示：** 在尝试内核漏洞之前，请务必使用 `systeminfo` 检查是否已打相关补丁。贸然执行漏洞利用程序可能会导致系统蓝屏（BSOD）

**第四步：凭据窃取与重用**

如果以上方法都失败了，或者你已经获得了管理员权限，下一步就是获取更多凭据，为横向移动做准备

**1. LSASS 进程内存转储**

Windows 在 `lsass.exe` 进程中缓存了用户的明文密码、NTLM 哈希和 Kerberos 票据

- **利用方式：** 使用 **Mimikatz** 或其他工具，在拥有 `SeDebugPrivilege` 特权时，可以从 `lsass.exe` 进程中直接抓取凭据
  - `sekurlsa::logonpasswords`：抓取所有已登录用户的明文密码和哈希
  - `lsass.exe` 内存转储：如果无法直接运行 Mimikatz，可以先使用 `procdump.exe` 转储 `lsass.exe` 进程内存，然后在另一台机器上离线分析

**2. SAM 和 SYSTEM 注册表文件**

SAM 文件包含了本地用户的密码哈希，而 SYSTEM 文件包含了用于解密 SAM 的密钥

- **利用方式：** 使用 `reg save` 命令将这两个文件导出，然后使用工具（如 `samdump2` 或 `impacket` 的 `secretsdump.py`）离线解密哈希