// 不安全的代码示例
document.getElementById('message').innerHTML = decodeURIComponent(location.search.split('msg=')[1]);