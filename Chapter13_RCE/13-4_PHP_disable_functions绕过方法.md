### PHP disable_functions() 绕过方法

**1. LD_PRELOAD 环境变量劫持**

**原理：** `LD_PRELOAD` 是一个环境变量，它允许用户在程序运行前指定一个或多个动态链接库（.so文件）。这些库中的函数会优先于系统默认的库被加载。我们可以利用这一点，编写一个恶意的动态链接库，其中包含一个与常用系统函数（如 `getuid`、`geteuid` 等）同名的恶意函数

**绕过步骤：**

1. 编写一个 C 语言恶意代码，利用 `__attribute__((constructor))` 在库加载时执行系统命令，并将其编译成一个 `.so` 文件
2. 在 PHP 中，通过 **`putenv()`** 函数设置 `LD_PRELOAD` 环境变量，指向我们恶意的 `.so` 文件
3. 触发一个可以调用系统函数的 PHP 函数，例如 `mail()` 或 `exec()`。当这个函数被调用时，`LD_PRELOAD` 就会生效，我们的恶意代码会被执行

这种方法非常有效，但前提是 `putenv()` 或类似的函数没有被禁用，并且目标服务器支持动态链接

**2. ImageMagick 命令执行漏洞**

**漏洞名称：** CVE-2016-3714 (ImageTragick) **原理：** ImageMagick 是一个用于创建、编辑和转换图像的流行开源软件。该漏洞允许攻击者通过处理一个特制的图像文件（例如 SVG、MVG 格式）来执行任意系统命令

**绕过步骤：**

1. 制作一个恶意的 SVG 或 MVG 格式图像文件，其中嵌入了命令执行 Payload。例如：`"push graphic-context viewbox 0 0 640 480 fill 'url(https://example.com/)'"`，`url()` 后面可以接 `file://` 或 `http://` 等协议，通过 `pipe` 触发命令
2. 在 PHP 中，如果使用了 **`Imagick`** 扩展来处理上传的图像文件，当调用 `readImage()` 或 `pingImage()` 等函数时，就会触发漏洞，执行恶意 Payload

这种方法主要针对使用了特定软件版本且存在漏洞的目标，属于典型的“Nday”漏洞利用

**3. Windows 系统组件 COM 绕过**

**原理：** 在 Windows 环境下，**`COM`** (Component Object Model) 是一个重要的技术。PHP 的 `COM` 扩展可以用来创建和调用 COM 组件。其中，`WScript.Shell` 这个组件可以用来执行系统命令

**绕过步骤：**

1. 在 PHP 代码中，通过 `new COM('WScript.shell')` 创建一个 `WScript.Shell` 对象
2. 调用这个对象的 `run()` 或 `exec()` 方法来执行命令。例如：`$shell = new COM('WScript.shell'); $shell->Run('cmd.exe /c "whoami"');`
3. 这种方法依赖于 PHP 的 `COM` 扩展是否启用，以及目标服务器是否是 Windows 系统

**4. PHP 7.4 FFI 绕过**

**原理：** **`FFI`** (Foreign Function Interface) 是 PHP 7.4 引入的一个扩展，允许 PHP 代码直接调用 C 语言的函数和数据结构，而无需编写额外的 C 语言扩展。这大大增强了 PHP 的能力，同时也带来了安全风险

**绕过步骤：**

1. 使用 `FFI::cdef()` 函数加载 `libc` 库，并定义 `system` 或 `exec` 函数
2. 然后就可以像调用 PHP 函数一样调用 C 语言的 `system` 函数来执行命令
3. 例如：`$ffi = FFI::cdef('int system(const char *command);', 'libc.so.6'); $ffi->system('whoami');`
4. 这种方法非常强大，但前提是 `FFI` 扩展已启用且未被禁用

**5. Bash 破壳漏洞**

**漏洞名称：** CVE-2014-6271 (Shellshock) **原理：** 这是一个在 Bash 4.3 及更早版本中的高危漏洞。它允许攻击者通过环境变量，向 Bash 注入并执行任意代码

**绕过步骤：**

1. 在 PHP 中，使用 `putenv()` 设置一个特殊的恶意环境变量
2. 例如：`putenv("test=() { :;}; echo 'VULNERABLE'");`
3. 随后，调用任何可以调用 Bash 的函数，例如 `mail()` 或 `exec()`。当 Bash 被调用时，它会解析环境变量，触发漏洞，执行恶意 Payload

**6. `imap_open()` 绕过**

**漏洞名称：** CVE-2018-19518 **原理：** 在 PHP 5.x 和 7.x 版本中，`imap_open()` 函数存在一个漏洞。当处理一个特定的 IMAP 协议 URL 时，它会调用 `rsh` 或 `ssh` 命令来连接远程服务器，从而导致命令执行

**绕过步骤：**

1. 在 PHP 中调用 `imap_open()` 函数，并传入一个恶意构造的 IMAP URL
2. 例如：`imap_open('-oProxyCommand=whoami', 'a', 'a');`
3. `-oProxyCommand` 是一个 SSH 选项，它允许在连接前执行命令。`imap_open()` 会调用 `rsh` 或 `ssh`，从而触发这个命令执行
4. 这种方法依赖于目标服务器上 `imap` 扩展是否启用

**7. `pcntl` 插件绕过**

**原理：** **`pcntl`** 是 PHP 的一个进程控制扩展，它提供了一系列与进程相关的函数，例如 `pcntl_exec()`

**绕过步骤：**

1. `pcntl_exec()` 函数可以用来在当前进程中执行一个指定的程序
2. 例如：`pcntl_exec('/bin/sh', array('-c', 'whoami'));`
3. `pcntl_exec()` 会直接替换当前 PHP 进程，而不会像 `system()` 那样创建一个新的子进程。这种方法非常隐蔽，且通常不被 `disable_functions` 列表所限制