const express = require('express')
const router = express.Router()
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

router.use(bodyParser.urlencoded({ extended: true }))
router.use(cookieParser())

// 设置一个简单的登录页面
router.get('/csrf/login', (req, res) => {
	res.send(`<form action="/csrf/login" method="post">
              <input type="text" name="username" placeholder="账号" />
              <input type="password" name="password" placeholder="密码" />
              <button type="submit">登录</button>
            </form>`)
})

// 登录接口，简化处理，实际开发需要安全验证
router.post('/csrf/login', (req, res) => {
	// 设置简单的登录Cookie
	// res.cookie('auth', 'dummy-token', { sameSite: 'strict' }) // 防止csrf
	res.cookie('auth', 'dummy-token')
	res.send('登录成功')
})

// 受保护的操作
router.post('/csrf/action', (req, res) => {
	console.log(req.cookies)
	const token = req.cookies.auth
	if (token === 'dummy-token') {
		res.status(200).send({ message: '执行成功' })
	} else {
		res.send('验证未通过')
	}
})

// 导出路由器
module.exports = router
