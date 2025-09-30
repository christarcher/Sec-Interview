### Java invoke 反射具体利用

**1. `invoke` 反射的基础**

`java.lang.reflect.Method` 类的 `invoke()` 方法是反射的核心。它的签名如下：

```java
public Object invoke(Object obj, Object... args)
    throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
```

- `obj`：要调用方法的对象实例。如果是静态方法，`obj` 可以为 `null`
- `args`：调用方法时传入的参数

**利用方式**：通过 `invoke`，你可以在不知道类名、方法名和参数类型的情况下，动态地调用任何方法。这正是它成为漏洞利用利器的原因

**2. `invoke` 反射在反序列化中的利用**

在 Java 反序列化漏洞中，`invoke` 反射通常用于构建 **Gadget Chain**，实现远程代码执行（RCE）

**场景**：`Apache Commons Collections` 反序列化漏洞

- **核心 Gadget**：`InvokerTransformer`。它的 `transform()` 方法正是利用了 `invoke` 反射
- **攻击链**：
  1. 攻击者构造一个 `ChainedTransformer`，并将其与一系列 `Transformer` 组合
  2. 其中，最关键的 `Transformer` 就是 `InvokerTransformer`。攻击者会多次使用它来构建命令执行链
  3. **第一次 `invoke`**：
     - `Transformer` 实例：`new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null})`
     - 攻击者传入 `java.lang.Runtime` 类作为 `obj`，`invoke` 方法会调用 `java.lang.Runtime.class.getMethod("getRuntime")`
     - 这会返回一个 `Method` 对象，指向 `getRuntime()` 方法
  4. **第二次 `invoke`**：
     - `Transformer` 实例：`new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null})`
     - 攻击者传入上一步返回的 `Method` 对象作为 `obj`，`invoke` 方法会调用 `getRuntime().invoke(null, null)`
     - 这会返回一个 `Runtime` 实例
  5. **第三次 `invoke`**：
     - `Transformer` 实例：`new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"whoami"})`
     - 攻击者传入上一步返回的 `Runtime` 实例作为 `obj`，`invoke` 方法会调用 `runtime.exec("whoami")`
- **最终结果**：通过三次 `invoke` 反射的串联，实现了从获取 `Runtime` 实例到执行系统命令的完整攻击过程

**3. `invoke` 反射在表达式注入中的利用**

在表达式语言（如 SpEL、OGNL）注入漏洞中，`invoke` 反射是实现 RCE 的主要手段

**场景**：Spring SpEL 注入

- **攻击 Payload**：`T(java.lang.Runtime).getRuntime().exec("whoami")`
- **攻击链**：当 Spring 解析这个表达式时，它会执行以下步骤：
  1. **`T()`**：表达式引擎通过反射找到并获取 `java.lang.Runtime` 类对象
  2. **`getRuntime()`**：表达式引擎调用 `java.lang.Runtime` 类的**静态方法** `getRuntime()`。这个过程在底层也是通过 `invoke` 反射实现的，传入 `null` 作为对象实例
  3. **`exec()`**：表达式引擎调用上一步返回的 `Runtime` 实例的 `exec("whoami")` 方法
- **最终结果**：成功执行系统命令