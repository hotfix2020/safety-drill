const express = require('express')
const cookieParser = require('cookie-parser')

const app = express()
const port = 443
const host = "0.0.0.0"

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

app.use((err, req, res, next) => {
  console.log('<-----------------------error start----------------------->')
  console.error(err.stack); // 打印错误栈信息到控制台
  console.log('<-----------------------error end----------------------->')
  res.status(500).send('Something broke!'); // 发送一个500响应
});


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

app.listen(port, host, () => {
	console.log(`Server listening at ${host}:${port}`)
})

process.on('uncaughtException', (err) => {
  console.error('有一个未被捕获的异常');
  console.log(err);
  process.exit(1); // 退出程序
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('没有处理的拒绝', promise, 'reason:', reason);
  // 应用的退出逻辑或重启逻辑
});
