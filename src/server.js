require(“dotenv”).config();
const express = require(“express”);
const cors = require(“cors”);
const { v4: uuidv4 } = require(“uuid”);
const { Scanner } = require(”./scanner”);
const { isValidUrl, timestamp } = require(”./utils”);
const { extractPathsFromHTML, detectPatterns } = require(”./extractors”);

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT) || 3001;
const HOST = process.env.HOST || “0.0.0.0”;
const MAX_THREADS = parseInt(process.env.MAX_THREADS) || 50;
const MAX_QUEUE = parseInt(process.env.MAX_QUEUE) || 10;
const CORS_ORIGIN = process.env.CORS_ORIGIN || “*”;

// ─── App ─────────────────────────────────────────────────────────────────────

const app = express();

app.use(cors({
origin: CORS_ORIGIN === “*” ? true : CORS_ORIGIN,
credentials: CORS_ORIGIN !== “*”,
methods: [“GET”, “POST”, “OPTIONS”],
allowedHeaders: [“Content-Type”],
exposedHeaders: [“X-Scan-Id”],
}));
app.use(express.json({ limit: “10mb” }));
app.use(express.urlencoded({ extended: true, limit: “10mb” }));

// Track active scans
const activeScans = new Map();

// ─── Health Check ────────────────────────────────────────────────────────────

app.get(”/api/health”, (req, res) => {
res.json({
status: “ok”,
version: “1.0.0”,
activeScans: activeScans.size,
uptime: process.uptime(),
});
});

// ─── Start Scan (SSE Stream) ─────────────────────────────────────────────────

app.post(”/api/scan”, (req, res) => {
const { target, wordlist, threads, options } = req.body;

// Validate
if (!target || typeof target !== “string” || target.trim().length === 0) {
return res.status(400).json({ error: “Target is required” });
}

const isSource = !target.startsWith(“http”);
if (!isSource && !isValidUrl(target)) {
return res.status(400).json({ error: “Invalid target URL” });
}

if (activeScans.size >= MAX_QUEUE) {
return res.status(429).json({ error: “Scan queue full, try later” });
}

const threadCount = Math.min(Math.max(1, parseInt(threads) || 10), MAX_THREADS);
const scanId = uuidv4();

// Parse wordlist
const paths = Array.isArray(wordlist)
? wordlist
: typeof wordlist === “string”
? wordlist.split(”\n”).map((l) => l.trim()).filter(Boolean)
: [];

// SSE setup
res.writeHead(200, {
“Content-Type”: “text/event-stream”,
“Cache-Control”: “no-cache”,
Connection: “keep-alive”,
“X-Scan-Id”: scanId,
“Access-Control-Allow-Origin”: “*”,
“Access-Control-Expose-Headers”: “X-Scan-Id”,
});

const sendSSE = (event, data) => {
res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
};

sendSSE(“init”, { scanId, target: isSource ? “source_analysis” : target, threads: threadCount });

// Create scanner
const scanner = new Scanner({
target,
wordlist: paths,
threads: threadCount,
options: {
sensitive: options?.sensitive ?? true,
patterns: options?.patterns ?? true,
security: options?.security ?? true,
},
emit: (event, data) => {
try {
sendSSE(event, data);
} catch {
// Client disconnected
}
},
});

activeScans.set(scanId, scanner);

// Handle client disconnect
req.on(“close”, () => {
scanner.abort();
activeScans.delete(scanId);
});

// Run scan
scanner.run().then((results) => {
sendSSE(“done”, results);
res.end();
activeScans.delete(scanId);
}).catch((err) => {
sendSSE(“error”, { message: err.message });
res.end();
activeScans.delete(scanId);
});
});

// ─── Abort Scan ──────────────────────────────────────────────────────────────

app.post(”/api/scan/:scanId/abort”, (req, res) => {
const scanner = activeScans.get(req.params.scanId);
if (!scanner) {
return res.status(404).json({ error: “Scan not found” });
}

scanner.abort();
activeScans.delete(req.params.scanId);
res.json({ status: “aborted”, scanId: req.params.scanId });
});

// ─── Extract Paths (stateless) ───────────────────────────────────────────────

app.post(”/api/extract-paths”, (req, res) => {
const { source, baseUrl } = req.body;

if (!source || typeof source !== “string”) {
return res.status(400).json({ error: “Source code is required” });
}

try {
const paths = extractPathsFromHTML(source, baseUrl || “”);
const uniquePaths = […new Set(paths)];

```
res.json({
  count: uniquePaths.length,
  paths: uniquePaths.map((p, i) => ({
    id: i,
    path: p,
    type: p.startsWith("http") ? "absolute" : "relative",
  })),
});
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ─── Detect Patterns (stateless) ─────────────────────────────────────────────

app.post(”/api/detect-patterns”, (req, res) => {
const { content, source } = req.body;

if (!content || typeof content !== “string”) {
return res.status(400).json({ error: “Content is required” });
}

try {
const patterns = detectPatterns(content, source || “manual_input”);

```
res.json({
  count: patterns.length,
  patterns,
  critical: patterns.filter((p) => p.severity === "critical").length,
  high: patterns.filter((p) => p.severity === "high").length,
});
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ─── Quick URL Check (single URL) ───────────────────────────────────────────

app.post(”/api/check-url”, async (req, res) => {
const { url, followRedirects } = req.body;

if (!url || !isValidUrl(url)) {
return res.status(400).json({ error: “Valid URL is required” });
}

try {
const { requestWithRedirects, createHttpClient } = require(”./scanner”);
const client = createHttpClient();
const result = await requestWithRedirects(client, url);

```
if (result.error) {
  return res.json({ error: result.error, chain: result.chain });
}

// Detect patterns in response
const patterns = detectPatterns(result.body || "", url);

res.json({
  url,
  status: result.status,
  size: result.size,
  contentType: result.contentType,
  chain: result.chain,
  finalUrl: result.finalUrl,
  hash: result.hash,
  patterns: patterns.length > 0 ? patterns : undefined,
  headers: result.headers,
});
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ─── List Active Scans ───────────────────────────────────────────────────────

app.get(”/api/scans”, (req, res) => {
const scans = [];
activeScans.forEach((scanner, id) => {
scans.push({
id,
target: scanner.target,
stats: scanner.stats,
});
});
res.json({ activeScans: scans });
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────

app.use((req, res) => {
res.status(404).json({ error: “Not found” });
});

// ─── Error Handler ───────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
console.error(`[${timestamp()}] Error:`, err.message);
res.status(500).json({ error: “Internal server error” });
});

// ─── Start Server ────────────────────────────────────────────────────────────

app.listen(PORT, HOST, () => {
console.log(`╔══════════════════════════════════════════════╗ ║                                              ║ ║   ██████╗ ██╗  ██╗████████╗ ██████╗  ██████╗ ║ ║  ██╔═████╗╚██╗██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗║ ║  ██║██╔██║ ╚███╔╝    ██║   ██║   ██║██║   ██║║ ║  ████╔╝██║ ██╔██╗    ██║   ██║   ██║██║   ██║║ ║  ╚██████╔╝██╔╝ ██╗   ██║   ╚██████╔╝╚██████╔╝║ ║   ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ║ ║                                              ║ ║  Bug Bounty Recon Suite v1.0                 ║ ║  Server: http://${HOST}:${PORT}                    ║ ║                                              ║ ╚══════════════════════════════════════════════╝`);
});

module.exports = app;
