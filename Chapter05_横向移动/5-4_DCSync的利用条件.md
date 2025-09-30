### DCSync 的利用条件

**域管理员组 (Domain Admins) 成员：** 默认情况下，此组的成员拥有执行 DCSync 所需的最高权限

**企业管理员组 (Enterprise Admins) 成员：** 此组的成员同样拥有对整个域林进行 DCSync 的权限

**根域控制器组 (Domain Controllers) 成员：** 域控制器本身需要执行此操作，因此它们拥有此权限

**拥有特定复制权限的账户：** 这是最常见的非高权限账户利用场景。攻击者需要找到或攻陷一个拥有以下两个权限的账户

- **"Replicating Directory Changes" (DS-Replication-Get-Changes)：** 允许账户请求目录服务中的所有对象和属性的更改
- **"Replicating Directory Changes All" (DS-Replication-Get-Changes-All)：** 允许账户请求所有目录服务中的密码哈希和敏感信息更改