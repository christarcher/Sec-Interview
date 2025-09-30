### MySQL 提权方式有哪些

**1. UDF 提权（User-Defined Function）**

UDF 提权是 MySQL 提权最常见且最有效的方式之一。它利用了 MySQL 允许用户通过 C/C++ 编写自定义函数并加载到数据库中执行的特性

- **前提条件：**

  - **高权限**：当前 MySQL 用户账户必须具备 `CREATE FUNCTION` 和 `FILE` 权限
  - **可写目录**：需要将恶意 UDF 库文件（`.dll` 或 `.so`）写入到 MySQL 插件目录中

- **攻击步骤：**

  1. **上传 UDF 库文件**：攻击者利用 SQL 注入或文件写入漏洞，将一个包含恶意系统命令执行功能的 UDF 库文件（例如 `lib_mysqludf_sys.so` 或 `mysql.dll`）上传到 MySQL 服务器的可写目录，通常是插件目录 (`/usr/lib/mysql/plugin/`) 或其他可写目录

  2. **创建自定义函数**：使用 SQL 语句，调用 `CREATE FUNCTION` 命令，将上传的 UDF 库文件中的恶意函数（如 `sys_exec` 或 `sys_eval`）注册为 MySQL 函数

     ```sql
     CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
     ```

  3. **执行系统命令**：通过调用新创建的函数，执行任意系统命令，从而实现提权

     ```sql
     SELECT sys_eval('whoami');
     ```

- **防御方法：**

  - **最小权限原则**：不要授予 MySQL 用户 `FILE` 或 `SUPER` 等高权限
  - **加固配置**：修改 `my.cnf` 文件，设置 `secure_file_priv` 为空或一个指定的安全目录，以限制文件导入导出功能

**2. MOF 提权（Managed Object Format）**

MOF 提权是针对 Windows 服务器的一种特定提权方式，利用了 Windows Server 2003/2008 上的一些服务配置不当

- **前提条件：**
  - **Windows 服务器**：目标服务器必须是 Windows 系统
  - **可写目录**：攻击者必须能够将恶意 MOF 文件写入到 `%systemroot%\system32\wbem\mof` 目录下
  - **MySQL 权限**：需要有 `FILE` 权限，以写入文件
- **攻击步骤：**
  1. **编写恶意 MOF 文件**：MOF 是 Windows 管理规范（WMI）使用的文件格式。攻击者可以编写一个恶意的 MOF 文件，让其在被系统加载时，自动执行一个指定的命令，比如创建一个新的管理员用户
  2. **上传 MOF 文件**：利用 `SELECT ... INTO OUTFILE` 语句，将恶意 MOF 文件写入到 `%systemroot%\system32\wbem\mof` 目录下
  3. **服务触发**：Windows 的 `CIMOM` 服务会周期性地扫描该目录下的 MOF 文件，并自动执行其内容。当恶意 MOF 文件被执行后，攻击者指定的命令就会被执行，从而实现提权
- **防御方法：**
  - **最小权限原则**：不要授予 MySQL 用户 `FILE` 权限
  - **更新系统**：该漏洞在较新的 Windows 系统版本中已被修复