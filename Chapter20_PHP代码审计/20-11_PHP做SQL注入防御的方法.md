### PHP 在做 SQL 注入防御时有哪些方法

**1. 使用预处理语句**

这是防御 SQL 注入的**首选方法**，也是最安全、最推荐的方式。预处理语句将 SQL 代码与数据**完全分离**，数据库会先编译SQL 模板，然后再将用户数据作为参数绑定进去。这样，无论用户输入什么，数据都只会被当作值来处理，而不会被当作SQL 代码的一部分

- **PDO (PHP Data Objects)**

  ```php
  // 创建PDO连接
  $pdo = new PDO("mysql:host=localhost;dbname=testdb", "username", "password");
  
  // 1. 准备SQL语句模板，使用 ? 占位符
  $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
  
  // 2. 绑定参数，将用户输入作为值传递
  $stmt->execute([$_POST['username']]);
  
  // 3. 获取结果
  $user = $stmt->fetch();
  ```

  PDO 是现代 PHP 开发中处理数据库连接和查询的标准库，它支持多种数据库，并且提供了强大的预处理功能

- **MySQLi**

  ```php
  // 创建MySQLi连接
  $mysqli = new mysqli("localhost", "username", "password", "testdb");
  
  // 1. 准备SQL语句模板，使用 ? 占位符
  $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
  
  // 2. 绑定参数，指定数据类型
  $stmt->bind_param("s", $_POST['username']); // "s" 表示 string
  
  // 3. 执行查询
  $stmt->execute();
  
  // 4. 获取结果
  $result = $stmt->get_result();
  $user = $result->fetch_assoc();
  ```

  MySQLi 是专为 MySQL 设计的扩展，也支持预处理语句

**2. 使用 ORM 框架**

如果你在使用像 **Laravel**、**Symfony** 或 **Yii** 这样的现代 PHP 框架，那么ORM（对象关系映射）库（如Eloquent或Doctrine）已经为你处理了预处理语句的复杂性

- **Laravel Eloquent 示例**

  ```php
  use App\Models\User;
  
  // Eloquent会自动使用预处理语句
  $user = User::where('username', $_POST['username'])->first();
  ```

  使用 ORM，你不再需要直接编写 SQL 语句，而是通过操作对象来完成数据库交互，这从根本上避免了 SQL 注入的可能性

**3. 数据转义**

在某些老旧的系统或特殊情况下，如果无法使用预处理语句，你必须对所有用户输入进行**转义**。转义的目的是将用户输入中的特殊字符（如单引号 `'`、双引号 `"`、反斜杠 `\` 等）进行处理，使它们失去原有的特殊含义，被数据库当作普通字符串来处理

- **使用 `mysqli_real_escape_string()`**

  ```php
  // 在使用前确保已经建立了MySQLi连接
  $username = mysqli_real_escape_string($conn, $_POST['username']);
  
  // 将转义后的变量拼接到SQL语句中
  $sql = "SELECT * FROM users WHERE username = '$username'";
  $result = mysqli_query($conn, $sql);
  ```

  这种方法**只在最后一道防线**使用，并且**不推荐**作为主要防御手段，因为它容易被遗漏，并且不同的数据库需要不同的转义函数，增加了开发者的负担

- **注意**：**绝对不要再使用 `addslashes()`**，因为它无法处理所有字符集，容易被绕过。`mysql_escape_string()` 也已经被废弃

**4. 最小权限原则**

这是一个重要的安全原则，可以降低 SQL 注入成功后的危害

- **不要使用 `root` 用户**或拥有所有权限的用户来连接数据库
- 为应用程序**创建专用的数据库用户**，并只赋予它完成任务所需的最小权限。例如，一个只读操作的脚本，其数据库用户就应该只有 `SELECT` 权限

| 防御方法   | 优点                                              | 缺点                                                     | 推荐度                 |
| ---------- | ------------------------------------------------- | -------------------------------------------------------- | ---------------------- |
| 预处理语句 | 最安全、最彻底的防御；将数据与代码分离；性能好。  | 语法相对复杂一些；无法用于某些动态 SQL（如表名、列名）。 | 最高                   |
| ORM 框架   | 从根本上杜绝 SQL 注入；开发效率高；代码可读性好。 | 需要学习框架；不适用于简单或无框架项目。                 | 非常高                 |
| 数据转义   | 适用于老旧系统或无框架的项目。                    | 容易遗漏；依赖开发者记忆；不彻底。                       | 低，仅作补充           |
| 最小权限   | 降低攻击后的危害。                                | 无法从根本上防御注入。                                   | 非常高（作为安全原则） |