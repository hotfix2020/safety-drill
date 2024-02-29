const express = require('express')
const cookieParser = require('cookie-parser')
const helmet = require('helmet')

const app = express()

// 获取命令行参数
const args = process.argv.slice(2) // 去掉前两个默认参数

const PORT = args[0] || 3000 // 如果命令行中提供了端口，使用该端口，否则默认为3000
const HOST = args[1] || 'localhost' // 如果命令行中提供了主机，使用该主机，否则默认为localhost
const IS_SECURITY = args[2] || '' // 默认打开安全配置

if (IS_SECURITY === 'open') {
	// 使用helmet提升安全性
	app.use(helmet())
	// 设置X-Frame-Options为DENY 不允许页面被嵌入到任何iframe中， SAMEORIGIN，只允许同源的页面嵌入
	app.use(
		helmet({
			xFrameOptions: { action: 'sameorigin' },
		})
	)
	// 设置Content-Security-Policy
	app.use(
		helmet({
			contentSecurityPolicy: {
				useDefaults: false,
				directives: {
					defaultSrc: ["'self'"], // 只允许执行同源的脚本
					scriptSrc: ["'self'", 'https://example.com'], // 允许执行这些源的脚本
					styleSrc: ["'self'", "'unsafe-inline'", 'https://example.com'], // 允许使用自身和指定example上的样式表
					objectSrc: ["'none'"], // 不允许<object>, <embed>, 和<applet>元素加载任何资源
					// upgradeInsecureRequests: [], // 将不安全的请求（http）升级为安全的请求（https）
					frameAncestors: ["'self'"], // 与X-Frame-Options的DENY相同，禁止页面被嵌入到任何iframe或frame中
				},
			},
		})
	)
}

app.use((err, req, res, next) => {
	console.log('<-----------------------error start----------------------->')
	console.error(err.stack) // 打印错误栈信息到控制台
	console.log('<-----------------------error end----------------------->')
	res.status(500).send('Something broke!') // 发送一个500响应
})

// 使用cookie-parser中间件
app.use(cookieParser())

// 自定义中间件来设置cookie
app.use((req, res, next) => {
	res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
	// 检查请求中是否已有cookie，如果没有则设置一个
	if (!req.cookies.token) {
		// 设置cookie，此处为示例，实际应用中可能没有cookie需要登录验证之类的
		res.cookie('token', Date.now(), { maxAge: 900000, httpOnly: false })
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

app.listen(PORT, HOST, () => {
	console.log(`Server listening at http://${HOST}:${PORT}`)
})

process.on('uncaughtException', err => {
	console.error('有一个未被捕获的异常')
	console.log(err)
	process.exit(1) // 退出程序
})

process.on('unhandledRejection', (reason, promise) => {
	console.error('没有处理的拒绝', promise, 'reason:', reason)
	// 应用的退出逻辑或重启逻辑
})
