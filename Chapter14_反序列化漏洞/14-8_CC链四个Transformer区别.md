### CC 链四个 Transformer 区别

**1. `InvokerTransformer`**

`InvokerTransformer` 是最核心、最通用、也最经典的 `Transformer`

- **原理**：它通过 **Java 反射**来调用一个对象的方法。在它的 `transform()` 方法中，你可以指定一个**类名**、**方法名**和**方法参数**。`InvokerTransformer` 会反射调用你指定的方法，并返回结果
- **如何触发命令执行**：
  1. 指定类为 `java.lang.Runtime`
  2. 指定方法为 `getMethod("getRuntime")`
  3. 指定参数为空
  4. 这会返回 `Runtime` 的实例
  5. 然后，再用另一个 `InvokerTransformer` 来调用 `exec()` 方法执行命令
- **用途**：它是 `CommonsCollections1` 利用链的核心组件。由于其功能过于强大和通用，它也是第一个被安全防御工具（如黑名单）重点关注和拦截的类。

**2. `InstantiateTransformer`**

`InstantiateTransformer` 的功能是**实例化一个新对象**

- **原理**：它的 `transform()` 方法会根据你指定的类名，通过反射来调用其构造函数，从而创建一个新的对象实例
- **如何触发命令执行**：
  1. 指定类为 `java.lang.Runtime`
  2. 指定构造函数为 `getConstructor()`
  3. 这会创建一个 `Runtime` 的实例
  4. 然后，再用 `InvokerTransformer` 来调用 `exec()` 方法
- **用途**：它通常用于在没有 `Runtime` 实例的情况下，创建一个新的 `Runtime` 实例。它在某些特定的 Gadget Chain 中用于绕过对 `InvokerTransformer` 的直接调用

**3. `ConstantTransformer`**

`ConstantTransformer` 是一个非常简单的 `Transformer`

- **原理**：它的 `transform()` 方法会**直接返回一个你预先设置好的常量**，而不进行任何额外的操作
- **如何触发命令执行**：它本身不能直接执行命令。它通常作为 Gadget Chain 中的**辅助组件**，用来提供一个常量值，比如提供一个 `Runtime` 实例
  1. 创建 `ConstantTransformer`，并传入 `Runtime.getRuntime()` 的实例
  2. 当 `transform()` 方法被调用时，它会返回这个 `Runtime` 实例
- **用途**：它常被用于组合其他 `Transformer`，为攻击链提供必要的对象实例。例如，在 `CommonsCollections4` 利用链中，它被用来提供 `Runtime` 实例，然后由 `InvokerTransformer` 来调用 `exec()`

**4. `ChainedTransformer`**

`ChainedTransformer` 的功能是将多个 `Transformer` **串联起来**

- **原理**：它的 `transform()` 方法会按顺序调用一个 `Transformer` 数组中的每一个 `Transformer`。第一个 `Transformer` 的输出会作为第二个 `Transformer` 的输入，以此类推
- **如何触发命令执行**：攻击者会将一个完整的攻击链（通常是 `ConstantTransformer` 和 `InvokerTransformer` 的组合）封装到一个 `ChainedTransformer` 中。当 `ChainedTransformer` 被反序列化时，它会按顺序调用这些 `Transformer`，最终触发命令执行
- **用途**：`ChainedTransformer` 是所有 `CommonsCollections` 利用链的**核心驱动器**。它扮演着“执行引擎”的角色，将整个多米诺骨牌串联起来，确保它们能按正确的顺序倒下

| Transformer            | 功能                | 在攻击链中的作用                           |
| ---------------------- | ------------------- | ------------------------------------------ |
| InvokerTransformer     | 反射调用方法        | 执行命令，是攻击链的核心                   |
| InstantiateTransformer | 实例化对象          | 创建实例，通常用于创建 Runtime 实例        |
| ConstantTransformer    | 返回常量值          | 提供常量对象，通常用于提供 Runtime 实例    |
| ChainedTransformer     | 串联多个Transformer | 驱动整个攻击链，按顺序执行每个 Transformer |