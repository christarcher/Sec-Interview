### Fastjson 漏洞原理

Fastjson 是阿里巴巴开源的一个高性能 JSON 解析库，它能够将 Java 对象序列化成 JSON 字符串，也能将 JSON 字符串反序列化成 Java 对象

Fastjson 漏洞的核心在于其 **自动类型转换（`AutoType`）** 功能

在 Fastjson 中，为了在反序列化时能够准确地恢复原始对象的类型，它提供了一个 `AutoType` 功能

当这个功能开启时，Fastjson 会在 JSON 字符串中加入一个特殊的字段 **`@type`**，用于标记这个 JSON 字符串对应的原始 Java 类的全限定名

```json
{"@type":"com.example.User","name":"张三","age":25}
```

当 Fastjson 反序列化这个 JSON 字符串时，它会首先解析 `@type` 字段，发现是 `com.example.User` 类型，然后创建一个 `User` 对象，并把 `name` 和 `age` 字段的值填充进去

Fastjson 在反序列化时，会无条件地信任并加载 `@type` 字段指定的类。攻击者可以利用这一点，构造一个恶意的 JSON 字符串，让 `@type` 字段指向一个可以执行恶意操作的 **Java 类**