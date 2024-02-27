const express = require('express')
const router = express.Router()
const bodyParser = require('body-parser')

router.use(bodyParser.json())

router.get('/xss/api/reflected', (req, res) => {
	// 反射用户输入
	const userInput = req.query.input
	res.json({ message: userInput })
})

// 导出路由器
module.exports = router

// <img src="invalid-image" onerror="alert(document.cookie);" />
