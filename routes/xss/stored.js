const express = require('express')
const bodyParser = require('body-parser')
const router = express.Router()

router.use(bodyParser.json()) // 解析JSON请求体

// 用于存储留言的数组
const messages = []

// 获取所有留言
router.get('/xss/api/messages', (req, res) => {
	res.json(messages)
})

// 提交新留言
router.post('/xss/api/messages', (req, res) => {
	const message = req.body.message
	if (message) {
		messages.push(message) // 将新留言添加到数组中
		res.status(201).send({ message: 'successfully.' })
	} else {
		res.status(400).send({ error: 'Message is required.' })
	}
})

// 导出路由器
module.exports = router

// <img src="invalid-image" onerror="alert(document.cookie);" />
// <script>alert('xss')</script>