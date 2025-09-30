### 如何判断靶标是否使用 FastJSON

**1. 报错信息**

通过构造特殊的请求来触发应用程序的报错，并从报错信息中寻找线索

- **构造畸形 JSON 数据**: 向目标API发送一个**格式错误的JSON**（例如，`{"a": 1, "b": "2",}`，多一个逗号）。如果服务器返回的错误信息中包含 `com.alibaba.fastjson`、`fastjson.JSONException` 或其他与 Fastjson 相关的关键字，那么就可以确定目标使用了 Fastjson

  ![](https://pic1.imgdb.cn/item/68cd62cac5157e1a881d5260.png)

- **尝试特定语法**: Fastjson 在处理一些特殊类型时有其独特的语法。你可以尝试发送一个包含 `@type` 字段的 JSON，例如 `{"@type":"java.lang.Class","val":"com.alibaba.fastjson.JSON"}`。如果服务器返回了与这个字段相关的解析错误，那么目标可能使用了 Fastjson

  ![](https://pic1.imgdb.cn/item/68cd6303c5157e1a881d52b8.png)

**2. 数值型数据**

FastJSON 会把 01 解析成 1

![](https://pic1.imgdb.cn/item/68cd635fc5157e1a881d535e.png)

FastJSON 1.2.70 会把 NaN 解析成 0

![](https://pic1.imgdb.cn/item/68cd659ac5157e1a881d58ab.png)

Fastjson 1.2.37 会抛出异常

![](https://pic1.imgdb.cn/item/68cd65f1c5157e1a881d59b9.png)

**3. 注释符**

FastJSON 支持注释符

![](https://pic1.imgdb.cn/item/68cd6618c5157e1a881d5a50.png)

**4. 单引号**

FastJSON 的 `Feature.AllowSingleQuote` 是默认开启的，支持使用单引号包裹字段名

![](https://pic1.imgdb.cn/item/68cd66afc5157e1a881d5d24.png)

**5. 缺失值**

FastJSON 正常解析，会把缺失的值忽略掉

![](https://pic1.imgdb.cn/item/68cd66e0c5157e1a881d5db4.png)

**6. 大小写**

FastJSON 在反序列化的时候，是对大小写不敏感的

![](https://pic1.imgdb.cn/item/68cd6725c5157e1a881d5e7a.png)

**7. 特殊符号**

FastJSON 1.2.36 版本及后续版本支持同时使用 `_` 和 `-` 对字段名进行处理

![](https://pic1.imgdb.cn/item/68cd680ec5157e1a881d61d4.png)
