### SQL 延时盲注 sleep() 被禁用怎么绕过

**1. 利用 BENCHMARK() 函数**

`BENCHMARK()` 函数是 MySQL 中一个非常有用的性能测试函数。它的作用是让一个函数重复执行多次，并返回执行时间。我们可以利用这个特性来造成可控的延时

- **原理:** `BENCHMARK(count, expr)` 会让 `expr` 表达式执行 `count` 次。如果我们让它执行一个耗时但无害的操作，就可以造成明显的延时

- **基本语法:** `BENCHMARK(count, expr)`

- **利用方式:**

  ```sql
  # 让 MD5('a') 重复执行 5,000,000 次，从而造成延时
  AND IF(ascii(substr(database(),1,1))=115, BENCHMARK(5000000, MD5('a')), 1)
  ```

  **解释:**

  - `IF(condition, true_value, false_value)`：这是一个条件判断语句
  - `ascii(substr(database(),1,1))=115`：这是我们的注入条件，判断数据库名的第一个字符的 ASCII 值是否为 115（即 `'s'`）
  - 如果条件为真，`BENCHMARK()` 函数被执行，导致页面延迟；如果条件为假，则立即返回 `1`，页面没有延迟

**2. 利用 GET_LOCK() 函数**

`GET_LOCK()` 函数是 MySQL 中的一个锁函数。它可以获取一个指定的锁，并在指定的超时时间内等待。如果锁被其他会话占用，它就会一直等待直到超时。我们可以利用这个特性来造成延时

- **原理:** `GET_LOCK(str, timeout)` 函数尝试获取一个名为 `str` 的锁，并等待 `timeout` 秒

- **利用方式:**

  ```sql
  # 如果条件为真，则获取一个名为 'a' 的锁并等待 5 秒
  AND IF(ascii(substr(database(),1,1))=115, GET_LOCK('a', 5), 1)
  ```

  这种方法的缺点是，如果多个请求同时执行，可能会因为锁竞争而造成不可预知的行为

**3. 利用 RLIKE/REGEXP 的正则特性**

当使用 `RLIKE` 或 `REGEXP` 进行正则表达式匹配时，如果正则表达式足够复杂，并且目标字符串足够长，也会造成明显的性能消耗，从而实现延时效果

- **原理:** 构造一个回溯（backtracking）量较大的正则表达式，让 MySQL 在匹配时消耗大量 CPU 资源

- **利用方式:**

  ```sql
  # 构造一个高回溯的正则表达式来消耗 CPU
  AND IF(ascii(substr(database(),1,1))=115, (SELECT concat(rpad('',4999999,'a'),rpad('',4999999,'a'),'a') RLIKE '(a.*)+(a.*)+'), 1)
  ```

  **解释:** `rpad()` 函数用于填充字符串，使其变得很长。`RLIKE '(a.*)+(a.*)+'` 是一个典型的回溯型正则表达式。当字符串很长时，匹配会非常耗时

**4. 利用笛卡尔积**

通过制造一个巨大的笛卡尔积，可以使查询的执行时间大大增加

- **原理:** 当两个大表没有关联地进行连接时，结果集的行数是两个表行数的乘积

- **利用方式:**

  ```sql
  # 使用 information_schema.tables 来制造一个笛卡尔积
  AND IF(ascii(substr(database(),1,1))=115, (SELECT COUNT(*) FROM information_schema.tables a, information_schema.columns b), 1)
  ```

  这种方法同样会造成明显的延迟，但查询结果可能会占用大量内存