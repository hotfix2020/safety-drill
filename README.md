# 前端安全演示分享

演示几种常见的前端安全威胁，包括跨站脚本攻击（XSS）、跨站请求伪造（CSRF）和点击劫持等，以及如何防御这些攻击。

## 目录

**routes：**
接口服务器

**public：**
演示页面等静态资源

## 本地运行

`node server 3000 localhost`

**开启csp等防御：**

`node server 3000 localhost open`

## 服务器运行

`node server 8000 0.0.0.0`

**开启csp等防御：**

`node server 8000 0.0.0.0 open`