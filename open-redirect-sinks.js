(async () => {
  const sinks = [
    "location",
    "location.host",
    "location.hostname",
    "location.href",
    "location.pathname",
    "location.search",
    "location.protocol",
    "location.assign",
    "location.replace",
    "open",
    "element.srcdoc",
    "XMLHttpRequest.open",
    "XMLHttpRequest.send",
    "jQuery.ajax",
    "$.ajax",
  ];

  const jsFiles = Array.from(document.scripts)
    .map((script) => script.src)
    .filter((src) => src && src.endsWith(".js"));

  if (jsFiles.length === 0) {
    console.log("No external .js files found");
    return;
  }

  let report = `🛡 JavaScript Open Redirect Sink Scan Report for ${location.origin}\n\n`;

  for (let i = 0; i < jsFiles.length; i++) {
    const url = jsFiles[i];
    try {
      const res = await fetch(url);
      const content = await res.text();
      const lines = content.split("\n");
      const foundMatches = [];

      lines.forEach((line, idx) => {
        sinks.forEach((sink) => {
          if (line.includes(sink)) {
            foundMatches.push(`[sink] ${sink} in line ${idx + 1}`);
          }
        });
      });

      report += `📄 File: ${url}\n`;
      if (foundMatches.length === 0) {
        report += `   🟢 No open redirect sink found.\n\n`;
      } else {
        foundMatches.forEach((match) => {
          report += `   🔹 ${match}\n`;
        });
        report += "\n";
      }
    } catch (err) {
      report += `❌ Error fetching ${url}\n`;
    }
  }

  // Create blob
  const blob = new Blob([report], { type: "text/plain" });

  // Generate origin-based filename
  const origin = location.origin
    .replace(/^https?:\/\//, "")
    .replace(/[:\/]/g, "_");
  const filename = `${origin}_open_redirect_scan.txt`;

  // Create download link
  const downloadLink = document.createElement("a");
  downloadLink.href = URL.createObjectURL(blob);
  downloadLink.download = filename;
  downloadLink.click();

  // Open in new tab
  const newTab = window.open();
  newTab.document.write(`<pre>${report.replace(/</g, "&lt;")}</pre>`);
})();
