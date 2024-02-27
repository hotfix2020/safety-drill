function submitInput() {
	const input = document.getElementById('userInput').value
	fetch(`/xss/api/reflected?input=${encodeURIComponent(input)}`)
		.then(response => response.json())
		.then(data => {
			document.getElementById('response').innerHTML = data.message
		})
}
