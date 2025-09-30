### Ajax 发送 POST 请求会发几个数据包

AJAX 发送一个 POST 请求，通常会发送**一个**数据包

这个数据包里包含了所有 POST 请求所需的信息，比如请求头（Headers）、请求体（Body）等。请求头里会指定 Content-Type 为 `application/x-www-form-urlencoded` 或 `application/json` 等，告诉服务器数据格式。请求体里则携带了实际要发送的数据。

**特殊情况：OPTIONS 预检请求**

不过，在某些跨域（CORS）场景下，浏览器在正式发送 POST 请求之前，会先发送一个 **OPTIONS** 请求，这个 OPTIONS 请求被称为“**预检请求**”（Preflight Request）

所以，如果满足以下任一条件，浏览器就会先发一个 OPTIONS 预检请求，然后再发 POST 请求：

- 使用了自定义请求头（如 `X-Requested-With`）
- Content-Type 不属于 `application/x-www-form-urlencoded`、`multipart/form-data` 或 `text/plain`。比如，使用了 `application/json`
- 请求方法为 PUT、DELETE 等，或 POST 请求与服务器的 API 路径不同

这个 OPTIONS 请求的目的是询问服务器是否允许当前域名、请求方法、自定义请求头等进行跨域操作。如果服务器返回的响应头里包含了允许的信息（如 `Access-Control-Allow-Origin`），浏览器才会继续发送实际的 POST 请求