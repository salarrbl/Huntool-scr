const http = require("http");
const url = require("url");

function getDomain(input) {
    try {
        return new URL(input).hostname;
    } catch {
        return "unknown";
    }
}

http.createServer((req, res) => {
    const q = url.parse(req.url, true).query;

    const site =
        q.site ||
        q.url ||
        q.h ||
        "unknown";

    const ua = req.headers["user-agent"] || "unknown";
    const ip = req.socket.remoteAddress;

    let domain = site;

    // if full URL is sent, extract domain
    try {
        domain = new URL(site).hostname;
    } catch {}

    const log = `
🔥 BLIND XSS DETECTED
➡ Site: ${domain}
➡ Raw: ${site}
➡ IP: ${ip}
➡ UA: ${ua}
➡ Time: ${new Date().toISOString()}
----------------------------
`;

    console.log(log);

    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
}).listen(8080, () => {
    console.log("🚀 XSS listener running on port 8080");
});
