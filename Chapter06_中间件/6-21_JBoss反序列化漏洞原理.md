### JBoss 反序列化漏洞原理

在 CVE-2017-7504 的利用中，攻击者通常会利用 **Apache Commons Collections** 库中的 Gadget Chain。这个库在许多 Java 应用中都非常常见，因此它成为了反序列化漏洞攻击的理想目标

攻击步骤如下：

1. **构造恶意对象：** 攻击者首先在本地构建一个恶意的 Java 对象，该对象利用 Apache Commons Collections 中的某些类，例如 `InvokerTransformer`。这个类可以用来反射调用任意方法，例如 `java.lang.Runtime.exec()`
2. **将对象序列化：** 攻击者将这个恶意对象序列化成字节流
3. **发送恶意请求：** 攻击者通过 JBoss Remoting 协议，将这个恶意的字节流发送给存在漏洞的 JBoss 服务器
4. **服务器反序列化：** JBoss 服务器接收到数据后，会调用 `ObjectInputStream.readObject()` 方法对其进行反序列化
5. **触发 Gadget Chain：** 在反序列化的过程中，Java 会按照字节流中的描述，依次还原对象并调用其中的方法。当执行到攻击者预设的 `InvokerTransformer` 时，它会反射调用 `java.lang.Runtime.exec()` 方法，并执行攻击者指定的命令