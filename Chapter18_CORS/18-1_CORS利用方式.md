### CORS 利用方式

**1. 简单 CORS 配置不当**

这是最常见、最基本的 CORS 漏洞，通常由于管理员或开发者为了方便，而设置了过于宽松的白名单

**a. `Access-Control-Allow-Origin: \*`**

这是最糟糕的配置。`*` 意味着服务器允许任何来源的域名进行跨域请求。攻击者可以利用这个漏洞，在自己的恶意网站上，发送带有受害者身份信息的请求到目标网站

- **利用方式：**

  - 攻击者在自己的恶意网站 `evil.com` 上，构造一个 JavaScript 请求
  - 该请求的目标是 `target.com`，并且带上了受害者的 `cookie`
  - 由于 `target.com` 允许所有来源，浏览器会发送请求，攻击者就可以获取到受害者的敏感信息，例如个人资料、账户余额等

- **PoC (Proof of Concept) 代码：**

  ```javascript
  var xhr = new XMLHttpRequest();
  xhr.withCredentials = true; // 携带 cookie
  xhr.open('GET', 'https://target.com/api/user-info', true);
  xhr.onload = function () {
      console.log(xhr.responseText); // 获取受害者数据
  };
  xhr.send();
  ```

**b. `Access-Control-Allow-Origin` 的动态配置**

有些网站会根据请求头的 `Origin` 字段，动态地将其回显到响应头中

- **原理：**
  - 攻击者发送一个请求，其 `Origin` 头部被设置为 `https://evil.com`
  - 如果服务器响应头中包含 `Access-Control-Allow-Origin: https://evil.com`，则说明存在漏洞
- **利用方式：**
  - 与 `*` 的情况类似，攻击者在 `evil.com` 上发起请求
  - 浏览器发送的请求头中包含 `Origin: https://evil.com`
  - 服务器将 `Origin` 的值原样返回，浏览器认为这是一个合法的跨域请求，从而执行
- **PoC 代码：**
  - 使用 Burp Suite 等工具，修改请求头的 `Origin` 字段，查看服务器的响应。

**2. 高级 CORS 漏洞利用**

除了基本的配置错误，还有一些更复杂的场景，利用了协议或 URL 解析的差异

**a. 协议绕过**

某些网站可能只对 `http` 或 `https` 协议的 `Origin` 做了严格限制，而忽略了其他协议

- **利用方式：**
  - 攻击者可以尝试将 `Origin` 设置为非标准的协议，例如 `http://` 变为 `http`、`https://` 变为 `https`、或者尝试 `file://` 等
  - 如果服务器的正则匹配不严谨，就可能被绕过

**b. 子域名或路径绕过**

一些网站的白名单只允许特定的子域名，但正则匹配存在缺陷

- **利用方式：**
  - 假设白名单只允许 `https://*.target.com`，攻击者可以尝试构造 `https://evil.com.target.com` 或 `https://target.com.evil.com`
  - 如果正则匹配不严谨，这些域名也可能被认为是合法的

**c. 端口绕过**

CORS 规范中，端口也是同源策略的一部分。但有些服务器在白名单中忽略了端口号

- **利用方式：**
  - 如果 `target.com` 允许 `Origin: https://target.com`，攻击者可以尝试使用 `https://target.com:8080` 作为 `Origin`
  - 如果服务器的白名单没有严格检查端口，这个请求可能会被通过