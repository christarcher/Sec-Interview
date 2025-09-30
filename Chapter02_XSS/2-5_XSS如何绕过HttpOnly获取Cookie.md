### XSS 如何绕过 HttpOnly 获取 Cookie

**XST** 是一种利用 HTTP `TRACE` 或 `TRACK` 方法的攻击，它在某些特定配置下可以绕过 HttpOnly。当一个网站允许 `TRACE` 请求时，攻击者可以通过以下步骤进行攻击：

1. 攻击者诱导受害者点击一个恶意链接或访问一个包含恶意脚本的页面
2. 恶意脚本向受害者的浏览器发送一个 `TRACE` 请求
3. 如果服务器没有正确配置，它可能会在 `TRACE` 响应中包含所有 HTTP 请求头，包括带有 HttpOnly 标志的 Cookie
4. 恶意脚本通过 JavaScript 读取 `TRACE` 响应的内容，从而获取到 Cookie

**防御方法：** 禁用 HTTP `TRACE` 和 `TRACK` 方法。现代服务器和框架默认都禁用了这些方法，但老旧的系统或错误配置的环境仍可能存在此漏洞