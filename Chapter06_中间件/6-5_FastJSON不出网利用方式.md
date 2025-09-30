### FastJSON 不出网利用方式

**1. 本地文件读写**

这是最常见的一种不出网利用方式。FastJson 的反序列化漏洞可以被利用来调用一些特定的类，这些类能够处理文件操作。

- **本地文件读取**: 我们可以利用 `com.sun.rowset.JdbcRowSetImpl` 类，在 `dataSourceName` 属性中构造一个特殊的 JNDI 字符串，例如 `rmi://localhost:1099/Evil`。在无法出网的情况下，这个 RMI 请求会失败，但如果我们将利用链和本地文件操作相结合，比如通过加载一些可以处理本地文件路径的类，理论上可以实现本地文件读取。一个更直接且知名的利用方式是利用 `javax.imageio.ImageIO` 类，通过 `read()` 方法加载一个恶意的 TIFF 或 GIF 文件，如果这个文件包含了特殊的 Payload，就能触发进一步的利用
- **本地文件写入**: 我们可以利用一些可以写文件的类，例如通过加载一些可以处理文件路径的类，并结合一些 **gadget** 链来构造一个可以写入文件的 Payload。这需要我们对 FastJson 的 Gadget 链有深入的理解，并找到合适的类来完成文件写入操作

**2. 命令执行**

如果能找到一个可以触发本地命令执行的 Gadget 链，那么即使不出网也能直接在目标服务器上执行命令

**`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`**: 这是 FastJson 漏洞利用中最经典的 Gadget 之一。通过控制 `_bytecodes` 字段，我们可以加载一个恶意的 Java 类。这个类在被加载和实例化时，可以在其静态代码块或者构造函数中执行本地命令，例如 `Runtime.getRuntime().exec("command")`

**`org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor`** 等其他 Gadget: 除了 `TemplatesImpl`，还有很多其他的 Gadget 链可以被利用来触发命令执行。这些 Gadget 链通常涉及到不同的库和类，但其核心思想都是通过反序列化加载一个恶意类，并在该类中执行命令

**3. 内存马注入**

这是一种更高级的无文件攻击方式

- **动态注入**: 我们可以利用 FastJson 的反序列化漏洞，通过一些特殊的 Gadget 链，在内存中动态地注入一个 **Webshell**。这个 Webshell 不会以文件的形式存在于磁盘上，而是直接运行在内存中。攻击者可以通过访问特定的 URL 或者发送特定的请求来与这个内存马进行交互，从而实现命令执行、文件管理等操作。这种方式由于没有落地文件，可以有效规避基于文件哈希或特征的检测
