### XStreadm 反序列化漏洞原理

**1. 核心原理：`readObject()` 方法和 Bad Gadget**

XStream 反序列化漏洞的原理与 `CommonsCollections` 漏洞非常相似，都是利用 Java 的**反序列化机制**和一些**恶意类（Gadget）**

1. **恶意 XML 构造**：攻击者首先会找到一个可以被利用的 Java 类（通常称为 “Bad Gadget”），这个类的 `readObject()` 方法（或其它类似方法，如 `finalize()`）在反序列化时会触发一些非预期的行为
2. **`readObject()` 的魔法**：当 XStream 对一个 XML 数据进行反序列化时，如果它解析到一个 `<object-name>` 标签，它会尝试实例化这个类，并调用其 `readObject()` 方法来填充数据
3. **触发命令执行**：如果攻击者能找到一个 Bad Gadget，它的 `readObject()` 方法能通过反射或其他方式，间接调用 `java.lang.Runtime.exec()`，那么就可以实现远程代码执行

与 `CommonsCollections` 不同的是，XStream 的攻击链并不局限于 `CommonsCollections` 库。**只要能找到一个可以被利用的类，就可以构造出攻击链。**

**2. 典型的 XStream 攻击链（`Groovy` 示例）**

一个经典的 XStream 攻击链利用了 `Groovy` 库，它曾经在 XStream 的黑名单之外

1. **恶意 XML 构造**：攻击者构造一个 XML，其中包含一个 `Groovy.lang.Closure` 对象。这个对象可以在其 `call()` 方法中执行任意代码

2. **利用`java.util.concurrent.ConcurrentHashMap`**：攻击者会将 `Groovy.lang.Closure` 封装到 `ConcurrentHashMap` 中，并利用其序列化特性

3. **XStream 反序列化**：当 XStream 解析 XML 时，它会创建 `ConcurrentHashMap` 实例，并填充其数据

4. **`Groovy` 代码执行**：在反序列化过程中，`ConcurrentHashMap` 会调用其内部的某些方法，这些方法会触发 `Groovy.lang.Closure` 的 `call()` 方法，从而执行攻击者预设的 Groovy 代码，例如：

   ```groovy
   "whoami".execute()
   ```

5. **远程代码执行**：最终，Groovy 代码会被执行，实现了 RCE

这个攻击链的本质是利用了 `Groovy.lang.Closure` 这个 Bad Gadget，结合 `ConcurrentHashMap` 的反序列化特性，在不被 XStream 黑名单拦截的情况下，触发了命令执行