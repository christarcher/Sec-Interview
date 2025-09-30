### 读取不到 hash 怎么绕过

**方法一：绕过 EDR/AV 和 LSAProtection**

这是最常见的挑战。大多数攻击者会使用 Mimikatz，但它常常被安全软件检测到

- **使用定制或混淆的工具：**
  - **Mimikatz 的变种：** 寻找或自己编译 Mimikatz 的混淆版本（如`P-Code`、`Minidump`）。这些版本可能没有被 EDR/AV 的签名库收录
  - **不依赖 Mimikatz 的替代工具：** 尝试使用其他开源工具，如 **`LaZagne`** 或 **`DonPAPI`**。这些工具采用不同的技术来提取凭据，可能绕过某些防御
- **使用内存转储（Memory Dumping）**
  - **`procdump.exe`：** 这是微软官方的工具，可以合法地转储进程内存。你可以使用它来转储 LSASS 进程，然后在另一台安全的机器上用 Mimikatz 的 **`sekurlsa::minidump`** 模块离线分析
  - **注意：** 尽管 `procdump` 是官方工具，但许多 EDR/AV 已经对其进行了监控。你需要小心使用
  - **手动转储：** 也可以使用 Powershell 或 C# 编写代码，直接调用 `MiniDumpWriteDump` API 来转储 LSASS 进程。这比使用现成的工具更隐蔽
- **进程注入与内存补丁**
  - 通过注入到合法的进程（如`svchost.exe`）中，然后从该进程内部转储 LSASS 内存，可以绕过一些基于进程行为的监控
  - **PPL（Protected Process Light）** 绕过：如果目标启用了 PPL，传统的注入方式会失败。可以尝试利用一些已知漏洞或驱动程序来提升权限并绕过 PPL。例如，使用一些内核驱动加载工具，在内核模式下操作

**方法二：不直接读取哈希，而是获取明文密码**

如果哈希实在无法获取，可以考虑获取用户的明文密码

- **键盘记录（Keylogging）：**
  - 部署一个键盘记录程序（如 **`PowerSploit`** 中的 `Get-Keystrokes`），记录用户在登录或输入密码时的按键
  - **优点：** 可以获取明文密码，且绕过了哈希的保护机制
  - **缺点：** 实时性差，需要等待用户输入密码，并且容易被杀毒软件检测
- **Hooking**
  - 通过在登录或凭据输入过程中，`Hook` 相关的 WinAPI 函数（如 `LsaLogonUser`），可以截取到明文密码或哈希
  - **优点：** 实时性高，可以在用户登录时立即获取凭据
  - **缺点：** 实现复杂，需要编写专门的代码，且容易被 EDR/AV 拦截

**方法三：利用其他机制获取凭据**

除了 LSASS，凭据还可能存储在其他地方

- **注册表（Registry）**
  - 某些应用程序（如 Putty、TeamViewer 等）可能会将连接密码以加密或明文形式存储在注册表中。可以使用 **`LaZagne`** 或其他专用工具扫描注册表
  - 例如：`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` 下可能会存储自动登录的明文密码
- **服务凭据（Service Credentials）**
  - 许多服务使用服务账户运行，这些账户的凭据通常存储在服务配置中。如果权限足够，可以枚举这些服务并尝试读取其配置
- **浏览器、邮件客户端和 FTP 客户端**
  - 浏览器（如 Chrome、Firefox）、邮件客户端（如 Outlook）和 FTP 客户端（如 FileZilla）通常会缓存用户的明文密码
  - 可以使用 **`Mimikatz`** 的 **`dpapi::`** 模块或专门的工具来解密这些存储的凭据