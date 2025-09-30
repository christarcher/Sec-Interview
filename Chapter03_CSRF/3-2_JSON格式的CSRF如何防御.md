### JSON 格式的 CSRF 如何防御

**1. 使用 CSRF Token**

这是最常见和最可靠的防御方法

- **工作原理**：

  1. 服务器在用户登录后，生成一个随机、唯一的 CSRF Token，并将其存储在**会话中**或**某个安全的地方**（如 `sessionStorage`）
  2. 服务器将 Token 发送给客户端
  3. 客户端在发起任何敏感操作的请求时，都必须将这个 Token 放在**HTTP 请求头**或 **POST 请求体**中
  4. 服务器接收到请求后，会验证请求中的 Token 是否与服务器上存储的 Token 相匹配。如果不匹配，则拒绝请求

- **在 JSON 请求中的实践**： 客户端的 JavaScript 代码在发起 POST 请求时，将 Token 放在一个自定义的 HTTP 头中，例如 `X-CSRF-TOKEN`

  ```js
  fetch('https://your-api.com/transfer', {
    method: 'POST',
    body: JSON.stringify({ to: 'attacker', amount: 1000 }),
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': 'your-generated-token'
    }
  });
  ```

  **防御原理**：攻击者无法从 `your-api.com` 域获取有效的 CSRF Token。由于同源策略的限制，恶意网站的 JavaScript 无法读取你的 API 返回的 HTML 或 JSON 数据，因此无法获取 CSRF Token。此外，即使是简单请求，自定义的 HTTP 头也会触发预检请求，同样会被 CORS 机制拦截

**2. 使用 SameSite Cookie**

前面我们讨论过 `SameSite` 属性。在 JSON API 的场景中，`SameSite=Lax` 同样是有效的防御

- **工作原理**： 将你的会话 Cookie 的 `SameSite` 属性设置为 `Lax` 或 `Strict`。当攻击者从恶意网站发起 POST 请求时，浏览器不会携带这个会话 Cookie。服务器在验证请求时，因为没有会话信息，会直接拒绝请求

  ```
  Set-Cookie: sessionid=xxxx; SameSite=Lax; Secure; HttpOnly
  ```

- **最佳实践**：

  - `SameSite=Strict`：提供了最强的防御，但可能影响用户体验
  - `SameSite=Lax`：在大多数情况下提供了足够的保护，同时不影响用户从其他网站通过 GET 链接跳转到你的网站

**3. 验证 Referer 或 Origin 头**

这种方法是辅助性的，但可以提供额外的安全层

- **工作原理**： 服务器检查请求头中的 `Referer` 或 `Origin` 字段，验证请求的来源是否为你的合法域名
  - `Referer`：表示发起请求的 URL
  - `Origin`：表示请求的来源域，通常用于 CORS 预检请求中
- **局限性**：
  - `Referer` 字段可以被一些浏览器或代理软件修改或删除
  - 这不是一个完全可靠的防御方法，应作为辅助手段而非主要策略