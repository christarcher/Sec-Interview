### PTH、PTT、PTK 三者区别

**Pass-the-Hash (PtH)**

**PtH** 是最广为人知的技术，它指的是一种攻击方法。攻击者通过窃取用户在内存中的 **NTLM 哈希**，并直接使用这个哈希来作为凭据进行身份验证，而不需要知道明文密码

- **工作原理：** 当 Windows 用户登录时，系统会生成一个 NTLM 哈希并存储在内存中。PtH 攻击者可以利用 Mimikatz 等工具从内存中抓取这个哈希，然后将它传递给目标服务（如 SMB、WMI），假冒该用户进行登录
- **应用场景：** 最典型的应用是横向移动。如果攻击者拿到了域管理员的 NTLM 哈希，就可以在其他机器上直接使用这个哈希来建立远程连接、执行命令，甚至完全控制整个域
- **常用工具：** **Mimikatz** 是 PtH 攻击的核心工具，它的 `sekurlsa::logonpasswords` 和 `sekurlsa::pth` 功能就是为此而生

**Pass-the-Ticket (PtT)**

**PtT** 则是利用 Kerberos 协议的攻击技术。它指的是攻击者窃取了用户在内存中的 **Kerberos 票据（Ticket Granting Ticket, TGT）**，然后将这个票据注入到当前会话中，从而获得访问权限

- **工作原理：** Kerberos 认证依赖于 TGT。当用户成功登录域时，域控制器会颁发一个 TGT。PtT 攻击者可以利用工具从内存中导出这个 TGT，并将其加载到另一台机器的内存中。加载后，该机器就可以向域内的其他服务发起访问请求，而不需要提供哈希或密码
- **与 PtH 的区别：**
  - **协议不同：** PtT 针对的是 **Kerberos** 协议，而 PtH 针对的是 **NTLM** 协议
  - **对象不同：** PtT 操作的是 **Kerberos 票据**，PtH 操作的是 **NTLM 哈希**
  - **更隐蔽：** Kerberos 认证通常比 NTLM 更难被检测，因为它不涉及明文密码或哈希在网络中的传输

**Pass-the-Key (PtK)**

**PtK** 是一种更新、更高级的哈希传递技术，它通常与 **AES 加密**有关。攻击者不再传递 NTLM 哈希或 Kerberos 票据，而是利用用户的 **AES 密钥**来伪造 Kerberos 认证过程

- **工作原理：** 在 Windows 2008 及更高版本的系统中，Kerberos 票据的加密和解密都可能使用 AES 密钥。PtK 攻击者从内存中提取出这个 AES 加密密钥，然后用它来伪造 Kerberos 票据，实现身份验证。这种方法通常用于绕过某些安全限制或在更现代的 Kerberos 环境中进行攻击
- **与 PtH/PtT 的区别：**
  - **对象不同：** PtK 利用的是 **AES 密钥**，而不是 NTLM 哈希或 Kerberos 票据
  - **安全性更高：** AES 密钥是更强大的加密凭据，攻击者拿到它后，几乎可以完全伪造 Kerberos 认证过程
  - **应用场景：** 在一些对 Kerberos 票据有额外安全控制的环境中，PtK 可能是更有效的选择

| 特性     | Pass-the-Hash (PtH)                | Pass-the-Ticket (PtT)                 | Pass-the-Key (PtK)               |
| -------- | ---------------------------------- | ------------------------------------- | -------------------------------- |
| 攻击对象 | NTLM 哈希                          | Kerberos 票据 (TGT)                   | AES 密钥                         |
| 利用协议 | NTLM                               | Kerberos                              | Kerberos                         |
| 核心工具 | Mimikatz、Impacket                 | Mimikatz、Impacket                    | Mimikatz                         |
| 常见场景 | Windows 2003/2008 老环境，横向移动 | Windows 2008+ Kerberos 环境，权限维持 | 现代 Kerberos 环境，更隐蔽的攻击 |
| 核心思想 | 伪造哈希                           | 注入票据                              | 伪造密钥                         |