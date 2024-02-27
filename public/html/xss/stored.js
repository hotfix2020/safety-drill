document.getElementById('messageForm').addEventListener('submit', function (e) {
	e.preventDefault()
	const messageContent = document.getElementById('messageInput').value
	fetch('/xss/api/messages', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ message: messageContent }),
	})
		.then(response => response.json())
		.then(data => {
			fetchMessages() // 重新加载留言
		})
		.catch(error => console.error('Error:', error))
})

function fetchMessages() {
	fetch('/xss/api/messages')
		.then(response => response.json())
		.then(messages => {
			const messagesList = document.getElementById('messagesList')
			messagesList.innerHTML = '' // 清空列表
			messages.forEach(message => {
				const li = document.createElement('li')
				li.innerHTML = message // 这里存在XSS漏洞
				messagesList.appendChild(li)
			})
		})
		.catch(error => console.error('Error:', error))
}

fetchMessages() // 页面加载时获取留言
