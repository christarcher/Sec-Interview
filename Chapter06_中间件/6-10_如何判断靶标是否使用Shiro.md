### 如何判断靶标是否使用 Shiro

**1. 查看 HTTP 请求和响应头**

这是最直接也最常用的方法。当一个网站使用 Shiro 框架时，它通常会在 HTTP 响应中设置一个特定的 Cookie

------

- **Shiro Cookie:** 检查 HTTP 响应头中的 `Set-Cookie` 字段。如果存在名为 **`rememberMe`** 的 Cookie，那么目标很可能使用了 Shiro 框架

  ```
  HTTP/1.1 200 OK
  Server: Apache-Coyote/1.1
  Set-Cookie: JSESSIONID=...; Path=/; HttpOnly
  Set-Cookie: rememberMe=...; Path=/; HttpOnly
  Content-Type: text/html;charset=UTF-8
  ```

  这个 `rememberMe` Cookie 是 Shiro 用来记住用户登录状态的。它的值是 Base64 编码的，这正是 Shiro-550 和 Shiro-721 漏洞的核心所在

**2. 发送特定请求并观察响应**

除了查看响应头，我们还可以通过发送一个带有特定 Cookie 的请求，并观察服务器的响应来进一步确认

- **发送带无效 RememberMe Cookie 的请求:** 发送一个 GET 请求到目标网站的任意页面，并在请求头中手动添加一个 **无效的 `rememberMe` Cookie**。例如，可以设置 `rememberMe=123`

  ```
  GET /index.jsp HTTP/1.1
  Host: example.com
  Cookie: rememberMe=123
  ```

- **观察响应头:** 如果目标使用了 Shiro，并且 `rememberMe` 验证失败，服务器通常会在响应头中返回一个 **`rememberMe=deleteMe`** 的 Cookie，来清除浏览器中无效的 Cookie。这是 Shiro 框架的一个典型特征

  ```
  HTTP/1.1 200 OK
  Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; HttpOnly
  ```

  如果看到了 `rememberMe=deleteMe`，几乎可以 100% 确定目标使用了 Shiro 框架

**3. 利用工具自动检测**

对于渗透测试工程师来说，手动测试虽然精确，但效率较低。我们可以使用一些自动化工具来快速检测

- **ShiroScan：** 这是一款专门用于检测 Shiro 漏洞的工具。它能够自动发送带有特定 Payload 的请求，并根据响应来判断目标是否使用了 Shiro，以及是否存在可利用的漏洞
- **Burp Suite 插件：** 许多 Burp Suite 插件，如 **Shiro-check**，都提供了自动检测功能。你只需在代理中浏览目标网站，插件就会自动分析请求和响应，并提示是否发现了 Shiro 的痕迹