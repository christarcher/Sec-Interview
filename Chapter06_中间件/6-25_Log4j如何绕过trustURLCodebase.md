### Log4j 如何绕过 trustURLCodebase

**`trustURLCodebase` 是什么？**

在 **JNDI**（Java Naming and Directory Interface）中，`trustURLCodebase` 是一个非常关键的 JVM 参数。它的作用是：

- 当 JNDI 客户端从远程服务器（例如 RMI 或 LDAP）获取一个 Java 对象时，如果这个对象在本地不存在，JNDI 客户端会根据远程服务器提供的 `codebase` URL，从**远程下载并加载**这个对象
- `trustURLCodebase` 这个参数决定了是否信任这个远程的 `codebase` URL
  - **`true`**（默认值，在 **JDK 8u191** 之前）：JVM 会无条件地信任并加载远程的代码
  - **`false`**（默认值，在 **JDK 8u191** 之后）：JVM 不会加载远程的代码，除非该代码被签名或来自于可信的本地路径

因此，`trustURLCodebase` 设为 `false` 是一个强大的防御措施，它从根本上阻止了 **JNDI 注入**通过远程加载恶意代码的方式来触发 RCE

**Log4j 绕过 `trustURLCodebase` 的原理**

尽管 `trustURLCodebase` 提供了强大的保护，但攻击者总能找到其他方法来绕过它。Log4j 漏洞的绕过方式，通常是利用 JNDI 注入的**其他特性**或寻找**本地可用的 Gadget Chain**

**1. 绕过原理一：利用本地 Gadget Chain**

这是最常见的绕过方式。如果 JNDI 客户端无法从远程下载恶意代码，那么攻击者就转而利用目标服务器**本地已有的**类库

- **攻击链**：
  1. 攻击者构造一个恶意的 JNDI 请求，例如 `ldap://attacker-ip/a`
  2. 在攻击者的 LDAP 服务器上，不返回一个远程 Codebase，而是返回一个指向**本地已存在的、可被反序列化利用的类**。例如，`javax.sql.DataSource` 或 `com.sun.rowset.JdbcRowSetImpl`
  3. 当 JNDI 客户端收到这个响应后，它会认为这个类是本地的，并进行实例化
  4. 在实例化或反序列化过程中，这些本地类中的**方法会被自动调用**，例如 `JdbcRowSetImpl` 的 `connect()` 方法会触发 JNDI 查找
  5. 攻击者可以在 JNDI 查找名中嵌入新的 JNDI URL，指向另一个恶意的服务，最终通过**反射**或**其他本地的 Gadget Chain**来执行命令
- **本质**：这种绕过方式的核心是**将远程代码加载变成了本地类调用**。它利用了**Java 反序列化**和**反射**，而不再依赖于远程 Codebase 的加载

**2. 绕过原理二：利用 `Serialized` 或 `Reference` 绕过**

在某些情况下，攻击者可以利用 JNDI 查找中的 `Serialized` 或 `Reference` 对象来绕过限制

- **攻击链**：
  1. 攻击者构造一个 JNDI 请求，其返回结果是一个 `Serialized` 对象
  2. `Serialized` 对象包含一个**序列化后的 Java 对象**
  3. 当客户端收到这个 `Serialized` 对象时，它会**直接对其中的数据进行反序列化**
  4. 攻击者可以在这个序列化数据中嵌入**任何恶意的 Gadget Chain**（例如 `CommonsCollections`），从而绕过 `trustURLCodebase` 的检查，直接触发反序列化漏洞
- **本质**：这种方法是将 JNDI 注入**转换成了传统的 Java 反序列化漏洞**。它绕过了 JVM 对远程代码加载的限制，转而利用了反序列化本身的设计缺陷