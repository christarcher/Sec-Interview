### MySQL 一个 @ 和两个 @ 的区别

**`@`（用户自定义变量）**

一个 `@` 符号代表**用户自定义变量**（User-Defined Variables）。这种变量是用户在当前会话中手动创建的，它的生命周期只存在于当前 MySQL 连接会话中。当会话结束时，变量也会被释放

**特点：**

- **创建与赋值**：可以使用 `SET` 或 `SELECT ... INTO` 语句来赋值
  - `SET @var_name = value;`
  - `SELECT column INTO @var_name FROM table;`
- **作用域**：仅在当前连接会话中有效。一个用户设置的 `@var_name` 无法被其他用户连接访问
- **用途**：常用于存储临时数据、在多条 SQL 语句中传递值，或者在存储过程、函数中作为临时变量

**示例：**

```sql
-- 在当前会话中设置一个变量
SET @total_price = 100;

-- 使用该变量进行计算
SELECT @total_price * 1.1 AS price_with_tax;

-- 在另一个新的连接中，@total_price 变量是不存在的，它的值为 NULL。
```

**`@@`（系统变量）**

两个 `@` 符号代表**系统变量**（System Variables）。这些变量是 MySQL 服务器预先定义好的，用于控制服务器的各种行为和状态

系统变量分为两种：

- **全局系统变量 (`@@global.var_name`)**：影响 MySQL 服务器的**所有会话**。需要有 `SUPER` 权限才能修改
- **会话系统变量 (`@@session.var_name` 或 `@@var_name`)**：仅影响**当前连接会话**。它的值会继承自全局变量，但可以在会话中被单独修改，且不会影响其他会话

**特点：**

- **查看**：可以使用 `SHOW VARIABLES` 或 `SELECT @@var_name` 来查看
- **修改**：使用 `SET` 语句进行修改
  - `SET GLOBAL max_connections = 200;`
  - `SET SESSION sql_mode = 'STRICT_TRANS_TABLES';`
  - `SET sql_mode = 'STRICT_TRANS_TABLES';`（`SESSION` 是默认的）
- **用途**：管理和调整数据库的各种配置，如最大连接数、字符集、缓冲区大小、SQL 模式等

**示例：**

```sql
-- 查看当前会话的字符集
SELECT @@character_set_client;

-- 查看全局最大连接数
SELECT @@global.max_connections;

-- 在当前会话中改变 SQL 模式，不影响其他会话
SET sql_mode = '';

-- 在所有会话中改变 SQL 模式 (需要 SUPER 权限)
SET GLOBAL sql_mode = 'STRICT_TRANS_TABLES';
```

| 特性     | @ (用户变量)                        | @@ (系统变量)                       |
| -------- | ----------------------------------- | ----------------------------------- |
| 全称     | User-Defined Variable               | System Variable                     |
| 创建者   | 用户自定义                          | MySQL 服务器预定义                  |
| 作用域   | 仅当前会话                          | 全局或当前会话                      |
| 主要用途 | 存储临时数据，方便在多条 SQL 中传递 | 管理和配置服务器行为                |
| 生命周期 | 会话结束即失效                      | 随服务器启动而加载                  |
| 可否修改 | 用户随时可改                        | 全局需要 SUPER 权限，会话可自由修改 |