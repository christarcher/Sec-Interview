### SQL 注入中 Post 和 Get 都做了防注入可采用什么方式绕过

许多 Web 应用程序不仅处理 POST 和 GET 数据，还会依赖于 HTTP 请求头中的信息。如果这些头信息没有经过严格的过滤，就可能成为注入点

- **User-Agent：** 很多网站会记录访问者的 User-Agent 信息。如果后台程序直接将 User-Agent 拼接到 SQL 查询中，就可能存在注入
- **X-Forwarded-For：** 这个头通常用于获取用户的真实 IP 地址。当网站部署了负载均衡或 CDN 时，它会记录用户的原始 IP。同样，如果处理不当，也可能成为注入点
- **Cookie：** 网站通常会使用 Cookie 来存储会话信息或其他用户数据。如果 Cookie 中的某个值直接参与了 SQL 查询，就可能被利用
- **Referer：** 网站会记录用户是从哪个页面跳转过来的。如果这个信息直接被用于查询，同样存在风险

**绕过方式：** 以 User-Agent 为例，你可以使用 Burp Suite 或其他抓包工具，在请求头中修改 User-Agent 的值，构造 SQL 注入 Payload。 例如：`User-Agent: ' OR 1=1--`