### 做过其他免杀吗，比如结合 CS 和 MSF 的

**MSFvenom 生成的 Payload 如何免杀？**

`msfvenom` 是一个强大的命令行工具，用于生成各种 Payload。它自带了多种编码器（Encoder），可以对 Payload 进行编码来绕过简单的静态特征码检测

- **编码器（Encoders）**：最简单的免杀方法是使用 `msfvenom` 自带的编码器，例如 `shikata_ga_nai`。这个编码器会对 Shellcode 进行多态编码，使得每次生成的 Payload 都不一样。但是，这种方法对于现代杀软来说已经不够了，因为杀软可以识别出编码器本身的行为模式
- **利用模板文件（Templates）**：你可以使用 `-x` 参数指定一个合法的可执行文件（例如 `notepad.exe`）作为模板，`msfvenom` 会将 Payload 注入到这个文件中。这样可以改变文件哈希，并且文件看起来像一个正常的程序
- **自定义 Shellcode 和加载器（Loader）**：
  - **生成纯 Shellcode**：使用 `-f raw` 或 `-f bin` 参数生成原始的 Shellcode 二进制文件，不带任何可执行文件头
  - **编写自定义加载器**：用 C++、C# 或 PowerShell 等语言编写一个加载器，它的任务是将 Shellcode 加载到内存并执行
  - **混淆加载器代码**：对加载器的代码进行混淆，比如使用花指令、字符串加密，以及反沙箱技术，来绕过杀软对加载器的静态检测
  - **内存执行**：加载器可以使用一些技巧，如 `VirtualAlloc`、`WriteProcessMemory` 和 `CreateThread` 等 API，来分配内存、将 Shellcode 写入，并在新线程中执行。由于 Shellcode 只是数据，不直接在文件中，静态杀软很难发现它

**Cobalt Strike 生成的 Payload 如何免杀？**

Cobalt Strike 生成的 Beacon Payload 同样非常强大，但它的默认 Payload 也会被杀软识别。CS 的免杀需要更高级的技巧

- **分离 Payload 和 Stager**：CS 的 Beacon Payload 通常分为两个阶段：一个小的 `Stager` 和一个大的 `Stageless` Payload。`Stager` 的任务是下载 `Stageless` Payload。你可以只生成 `Stager`，并对其进行混淆，而将 `Stageless` Payload 托管在自己的服务器上
- **使用自定义的 Shellcode 加载器（Loader）**：
  - CS 可以导出原始的 Shellcode。你可以使用前面提到的方法，用自定义的加载器来加载它
  - 很多攻击者会使用**反射式 DLL 注入**来加载 Payload。他们将 Shellcode 封装成一个 DLL，然后通过进程注入技术将 DLL 加载到另一个无害的进程中，以隐藏其行为
- **绕过行为检测**：CS 的 Beacon 在网络通信、权限提升等方面有很多特征，可能会被杀软的行为监控引擎捕获为了绕过这些检测：
  - **混淆网络通信**：使用自定义的通信协议或加密方式，使得流量看起来不像 Beacon 的默认流量
  - **进程注入的规避**：使用更隐蔽的进程注入技术，例如直接在内存中执行，而不是写入磁盘文件
  - **使用合法的证书和签名**：对 Payload 文件进行代码签名，增加其可信度
- **使用第三方工具**：除了自己编写加载器，还有很多开源或商业的工具专门用于混淆和打包 MSF/CS 的 Shellcode，例如 `sliver` 和 `Mythic` 等。这些工具通常包含了更高级的免杀技术