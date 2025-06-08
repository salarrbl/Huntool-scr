(async () => {
  const sources = ['location', 'document.URL', 'document.cookie', 'window.name'];
  const sinks = ['innerHTML', 'document.write', 'eval', 'setTimeout', 'setInterval'];

  const jsFiles = Array.from(document.scripts)
    .map(script => script.src)
    .filter(src => src && src.endsWith('.js'));

  if (jsFiles.length === 0) {
    console.log('no find external .js file');
    return;
  }

  let report = `🛡 JavaScript Source/Sink Scan Report\n\n`;

  for (let i = 0; i < jsFiles.length; i++) {
    const url = jsFiles[i];
    try {
      const res = await fetch(url);
      const content = await res.text();
      const lines = content.split('\n');
      const foundMatches = [];

      lines.forEach((line, idx) => {
        sources.forEach(src => {
          if (line.includes(src)) {
            foundMatches.push(`[source] ${src} in line ${idx + 1}`);
          }
        });
        sinks.forEach(sink => {
          if (line.includes(sink)) {
            foundMatches.push(`[sink] ${sink} in line ${idx + 1}`);
          }
        });
      });

      report += `📄 File: ${url}\n`;
      if (foundMatches.length === 0) {
        report += `   🟢 No source or sink found.\n\n`;
      } else {
        foundMatches.forEach(match => {
          report += `   🔹 ${match}\n`;
        });
        report += '\n';
      }

    } catch (err) {
      report += `❌ Error fetching ${url}\n`;
    }
  }

  // Create blob
  const blob = new Blob([report], { type: 'text/plain' });

  // Create download link
  const downloadLink = document.createElement('a');
  downloadLink.href = URL.createObjectURL(blob);
  downloadLink.download = 'js_scan_report.txt';
  downloadLink.click();

  // Open in new tab
  const newTab = window.open();
  newTab.document.write(`<pre>${report.replace(/</g, '&lt;')}</pre>`);
})();
