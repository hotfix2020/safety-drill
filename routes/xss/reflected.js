const express = require('express')
const router = express.Router()

// 定义根路由，捕获查询参数并反射到页面
router.get('/html/xss/reflected', (req, res) => {
    const userInput = req.query.userInput || 'Nothing to display';
    res.send(`
		<html>
			<title>反射型XSS攻击</title>	
			<body><h1>你的输入是：</h1><p>${userInput}</p></body>
		</html>
		`);
});

// 导出路由器
module.exports = router

// <img src="invalid-image" onerror="alert(document.cookie);" />
