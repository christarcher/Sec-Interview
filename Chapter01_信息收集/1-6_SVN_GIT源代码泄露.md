### 有没有了解过 SVN/GIT 源代码泄露

**SVN 源代码泄露**

SVN（Subversion）是一个集中式版本控制系统，它的核心目录是 `.svn`。当开发者在 Web 服务器的根目录下直接使用 `svn checkout` 或 `svn update` 命令时，`.svn` 目录及其所有子目录也会被同步到服务器上。如果 Web 服务器没有正确配置，这个隐藏目录就会被公网访问

**漏洞原理**

`/.svn/` 目录下存储了代码的元数据，这些数据通常以 `.svn/entries`、`.svn/text-base/` 等形式存在。攻击者可以通过递归下载这些文件来还原出整个代码库

- `/.svn/entries`：在 SVN 1.6 及更早版本中，这个文件包含了目录下所有文件的元数据，包括文件名、版本号、文件类型等。攻击者可以通过解析这个文件，获取所有文件的相对路径
- `/.svn/text-base/`：这个目录存储了每个文件的原始版本副本。文件名通常是 `filename.svn-base`。攻击者可以下载这些文件来获取源代码

**如何利用**

利用 SVN 源代码泄露，通常需要一个自动化工具来递归下载所有 `.svn` 目录下的文件，并根据元数据将它们重组为完整的代码库

1. **探测**：在目标网站 URL 后面加上 `/.svn/entries` 或 `/.svn/wc.db`（SVN 1.7+）来探测漏洞是否存在
   - `http://example.com/.svn/entries`
   - `http://example.com/some-dir/.svn/entries`
2. **自动化下载与重构**：使用 `svn-dumper`、`dvcs-ripper` 等工具。这些工具能够自动化完成下载和还原代码的过程

**Git 源代码泄露**

Git 是一个分布式版本控制系统，它的核心目录是 `.git`。和 SVN 类似，当开发者将代码直接在 Web 目录下进行 `git init` 或 `git clone` 操作时，`.git` 目录就会被创建并暴露出来

**漏洞原理**

`/.git/` 目录包含了 Git 版本库的所有信息，如对象（objects）、引用（refs）、索引（index）、配置文件（config）等。攻击者可以通过下载这些文件，利用 Git 内部的命令来还原代码

- `/.git/HEAD`：指向当前分支，可以确定当前分支名
- `/.git/index`：包含了暂存区的文件信息
- `/.git/objects/`：这个目录存储了所有的 Git 对象（包括文件、目录、提交等）。这是攻击者还原代码最关键的目录

**如何利用**

1. **探测**：在目标 URL 后面加上 `/.git/` 或 `/.git/config` 来探测漏洞
   - `http://example.com/.git/config`
   - `http://example.com/.git/HEAD`
2. **下载与重构**：同样可以使用 `dvcs-ripper` 或专门针对 Git 的工具。这些工具会下载 `.git` 目录下的所有文件，然后在本地创建一个 Git 仓库并还原出源代码
   - 通过 `git log` 查看提交历史
   - 通过 `git checkout` 切换到不同版本，获取所有版本的代码