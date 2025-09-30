### Nginx CRLF 注入原理

**什么是 CRLF？**

CRLF 是 **`Carriage Return Line Feed`** 的缩写，中文意思是**回车换行**

- `CR` (回车) 对应的十六进制是 `0x0D`，URL 编码是 `%0d`
- `LF` (换行) 对应的十六进制是 `0x0A`，URL 编码是 `%0a`

在 HTTP 协议中，CRLF 有着特殊的意义

HTTP 报文（包括请求头和响应头）都是由一行行文本组成的，而每一行的结束都由 **CRLF** 来标记

服务器解析 HTTP 报文时，就是通过 `CRLF` 来判断一行的结束和下一行的开始

**Nginx CRLF 注入原理**

Nginx CRLF 注入的根本原因是：**Nginx 将用户输入的数据直接或间接用在了 HTTP 响应头中，并且没有对数据中的特殊字符（尤其是 `%0d%0a`）进行严格过滤**

当攻击者在 URL 中注入 `%0d%0a` 时，Nginx 在构建 HTTP 响应头时会把这两个特殊字符当成普通字符串处理，直接写入响应头

服务器在解析这个响应时，看到 `%0d%0a` 就会将其**解析为真正的回车换行符**，从而导致：

- **HTTP 响应头提前结束**：服务器认为响应头已经结束了
- **攻击者可以注入新的响应头**：攻击者可以注入一个或多个新的响应头，例如 `Set-Cookie`、`Location` 等
- **攻击者可以注入完整的 HTTP 响应体**：攻击者甚至可以注入一个全新的 HTTP 响应体，实现**响应拆分**（HTTP Response Splitting）攻击

正常情况下，如果你访问 `http://example.com/redirect?url=/home`，服务器会返回

```apl
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.20.1
Location: /home
Content-Type: text/html
...
```

但是，如果攻击者构造一个恶意的 URL：`http://example.com/redirect?url=/home%0d%0aSet-Cookie:crlf=test`

```apl
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.20.1
Location: /home
Set-Cookie: crlf=test
Content-Type: text/html
...
```

你会发现，攻击者成功地在响应中注入了一个 **`Set-Cookie`** 响应头