### SQLMap 自带脚本有哪些

**1. 编码与混淆（绕过签名检测）**

这类脚本通过对注入语句进行编码或转换，来改变其特征，以躲避基于签名的检测

- `**charencode.py**`：对所有字符进行 URL 编码，适用于 URL 编码绕过
- `**randomcase.py**`：将 SQL 关键字的字母大小写随机化
  - **示例：** `SELECT` -> `sELeCT`
- `**space2comment.py**`：将空格替换为 SQL 注释 `/**/`
  - **示例：** `SELECT user FROM users` -> `SELECT/**/user/**/FROM/**/users`
- `**space2mysqlblank.py**`：用 MySQL 专有的空格字符（如 Tab、换行符）替换空格
- `**base64encode.py**`：对整个注入语句进行 Base64 编码。需要目标网站解码才能生效

**2. 空白字符与分隔符替换**

这类脚本利用不同数据库对空白字符的解析差异来绕过过滤

- `**apostrophemask.py**`：将单引号 `'` 替换为 UTF-8 编码的 `'`
- `**equaltolike.py**`：将等号 `=` 替换为 `LIKE` 关键字
  - **示例：** `id=1` -> `id LIKE 1`
- `**unionalltounion.py**`：将 `UNION ALL` 替换为 `UNION`，在某些情况下可能绕过过滤
- `**space2plus.py**`：将空格替换为加号 `+`，但需要注意这可能影响语句语义

**3. 语义与结构混淆**

这类脚本通过改变语句的逻辑结构，来使注入语句看起来像正常的查询

- `**between.py**`：将大于等于 `>=` 替换为 `BETWEEN`
  - **示例：** `id>=1` -> `id BETWEEN 1 AND 999`
- `**ifnull2casewhenisnull.py**`：将 `IFNULL(A, B)` 替换为 `CASE WHEN ISNULL(A) THEN B ELSE A END`

**4. 绕过 WAF 的特定脚本**

这些脚本通常针对特定的安全产品或通用 WAF 规则

- `**modsecurityzeroversioned.py**`：在 SQL 语句后添加 `/*-!11111*/` 来绕过 ModSecurity WAF 的特定规则
- `**xforwardedfor.py**`：在 HTTP 请求头中伪造 `X-Forwarded-For` 字段，以绕过基于 IP 的限制
- `**sp_password.py**`：在有效载荷的末尾添加 `sp_password` 来绕过 MS-SQL Server 的日志记录