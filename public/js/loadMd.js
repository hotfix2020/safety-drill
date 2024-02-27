document.addEventListener('DOMContentLoaded', (event) => {
  fetch('./README.md')
  .then(response => response.text())
  .then(data => {
    const markdownContent = data;
    const htmlContent = marked(markdownContent, {
      highlight: function (code, lang) {
        return hljs.highlightAuto(code, [lang]).value;
      }
    });
    document.getElementById('content').innerHTML = htmlContent;
    document.querySelectorAll('pre code').forEach((block) => {
      hljs.highlightBlock(block);
    });
  })
  .catch(error => console.error(error));
});