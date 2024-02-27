const express = require('express')
const cookieParser = require('cookie-parser')

const app = express()
const port = 8000

// 设置CSP以及其他安全相关的HTTP头部
// const helmet = require('helmet');
// app.use(helmet({
//   contentSecurityPolicy: {
//     directives: {
//       defaultSrc: ["'self'"], // 默认限制所有资源只能从当前源加载
//       scriptSrc: ["'self'", "cdnjs.cloudflare.com", "https://example.com"], // 允许执行自身和指定example上的脚本
//       styleSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "https://example.com"], // 允许使用自身和指定example上的样式表
//       imgSrc: ["'self'", "https://example.com"], // 允许加载自身和指定example上的图片
//       // 其他资源类型的策略...
//     },
//   },
// }));

// 引入xss模块
const xssReflectedRoutes = require('./routes/xss/reflected')
const xssStoredRoutes = require('./routes/xss/stored')

// 引入csrf模块
const csrfRoutes = require('./routes/csrf')

// 使用路由模块
app.use(xssReflectedRoutes)
app.use(xssStoredRoutes)
app.use(csrfRoutes)

// 用于托管静态文件
app.use(express.static('public'))

// 使用cookie-parser中间件
app.use(cookieParser())

// 自定义中间件来设置cookie
app.use((req, res, next) => {
	// 检查请求中是否已有cookie，如果没有则设置一个
	if (!req.cookies.token) {
		// 设置cookie，此处为示例，实际应用中可能没有cookie需要登录验证之类的
		res.cookie('token', Date.now(), { maxAge: 900000, httpOnly: true })
	}
	next()
})

app.listen(port, () => {
	console.log(`Server listening at http://localhost:${port}`)
})
