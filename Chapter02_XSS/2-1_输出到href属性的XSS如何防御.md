### 输出到 href 属性的 XSS 如何防御

**1. 严格的白名单验证**

这是最安全、最推荐的防御方法。**不要**试图去黑名单过滤，因为攻击者总能找到绕过的方法。相反，你应该只允许那些已知安全的协议和域名

- **只允许安全的协议**：只接受 `http` 和 `https` 协议。所有其他协议，特别是 `javascript:`、`data:`、`vbscript:` 等，都应该被拒绝
- **示例**：
  - **安全**：`https://www.example.com`
  - **不安全**：`javascript:alert(1)`

**实现方式**： 在后端代码中，你可以使用正则表达式或内置的 URL 解析函数来检查协议。例如，在 PHP 中可以这样做：

```php
function is_safe_url($url) {
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['scheme'])) {
        // 如果没有协议头，可能是相对路径，视为安全
        return true;
    }
    // 只允许 http 或 https 协议
    return in_array($parsed_url['scheme'], ['http', 'https']);
}

$user_input_url = $_GET['url'];
if (is_safe_url($user_input_url)) {
    // URL 安全，进行输出
    echo '<a href="' . htmlspecialchars($user_input_url) . '">Click Here</a>';
} else {
    // URL 不安全，拒绝或使用默认值
    echo '<a href="/default-page">Click Here</a>';
}
```

**2. 对所有 URL 进行 HTML 实体编码**

这是防御 XSS 的基本操作，但它**不足以**防御 `href` XSS。你仍然需要执行它，因为它能防止其他类型的 XSS 攻击htmlspecialchars()` 或 `htmlentities()` 可以将 `<`、`>`、`"` 等特殊字符转换为实体，防止它们被解释为 HTML 标签

- **正确做法**：将 URL 进行白名单验证后，再进行 HTML 实体编码

  - **示例**：

    ```php
    $safe_url = "https://example.com/page?param=<script>alert(1)</script>";
    echo '<a href="' . htmlspecialchars($safe_url) . '">Click Here</a>';
    ```

  - **结果**：浏览器渲染为 `<a href="https://example.com/page?param=<script>alert(1)</script>">Click Here</a>`。即使 URL 中包含恶意代码，它也不会被执行。但如果 URL 是 `javascript:alert(1)`，单独使用 `htmlspecialchars()` 是无效的

**3. CSP**

CSP 是一个强大的安全策略，可以从根本上限制页面可以加载和执行的资源。你可以设置一个 CSP 规则，明确禁止 `javascript:` 协议的 URI

- **在 HTTP 响应头中添加**： `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';`

  这条规则**不直接**阻止 `href` 中的 `javascript:`，但它可以与**不安全的内联脚本**（`unsafe-inline`）策略结合使用。一个更严格的 CSP 策略可以禁止内联脚本，从而让 `javascript:` 协议失效

- **一个更有效的 CSP 规则**： `Content-Security-Policy: default-src 'self'; script-src 'self';`

  这条规则禁止了所有内联脚本，包括 `javascript:` 协议，从而提供了额外的保护层。不过，这可能会对你的网站功能造成影响，需要在部署前进行全面测试