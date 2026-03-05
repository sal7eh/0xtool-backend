const axios = require(“axios”);
const pLimit = require(“p-limit”);
const { hashBody, normalizeUrl, timestamp, sleep } = require(”./utils”);
const { extractPathsFromHTML, detectPatterns, SENSITIVE_FILES } = require(”./extractors”);
const { analyzeSecurityHeaders, analyzeCookies, testAllowedMethods } = require(”./security”);

const DEFAULT_UA = process.env.USER_AGENT || “0xTool/1.0 (Bug Bounty Recon)”;
const DEFAULT_TIMEOUT = parseInt(process.env.REQUEST_TIMEOUT) || 10000;
const MAX_REDIRECTS = parseInt(process.env.MAX_REDIRECTS) || 10;

/**

- Create an axios instance with redirect tracking
  */
  function createHttpClient(config = {}) {
  const instance = axios.create({
  timeout: config.timeout || DEFAULT_TIMEOUT,
  maxRedirects: 0, // We track redirects manually
  validateStatus: () => true, // Accept all status codes
  headers: {
  “User-Agent”: config.userAgent || DEFAULT_UA,
  Accept: “*/*”,
  },
  // Don’t decompress automatically (to get real size)
  decompress: true,
  responseType: “text”,
  maxContentLength: 10 * 1024 * 1024, // 10MB max
  });

return instance;
}

/**

- Follow redirects manually and record the chain
  */
  async function requestWithRedirects(client, url, method = “GET”) {
  const chain = [];
  let currentUrl = url;
  let response = null;
  let hops = 0;

while (hops < MAX_REDIRECTS) {
try {
response = await client({
method,
url: currentUrl,
validateStatus: () => true,
});

```
  const status = response.status;
  const isRedirect = [301, 302, 303, 307, 308].includes(status);

  if (isRedirect && response.headers.location) {
    const nextUrl = new URL(
      response.headers.location,
      currentUrl
    ).href;

    chain.push({
      from: currentUrl,
      to: nextUrl,
      status,
    });

    currentUrl = nextUrl;
    hops++;
  } else {
    break;
  }
} catch (err) {
  return {
    error: err.code || err.message,
    chain,
    finalUrl: currentUrl,
  };
}
```

}

if (!response) {
return { error: “No response”, chain, finalUrl: currentUrl };
}

const body = typeof response.data === “string” ? response.data : JSON.stringify(response.data || “”);

return {
status: response.status,
statusText: response.statusText,
headers: response.headers,
size: Buffer.byteLength(body, “utf8”),
contentType: response.headers[“content-type”] || “unknown”,
body,
chain,
finalUrl: currentUrl,
hash: hashBody(body),
error: null,
};
}

/**

- Main scan orchestrator
  */
  class Scanner {
  constructor(config) {
  this.target = config.target;
  this.wordlist = config.wordlist || [];
  this.threads = config.threads || 10;
  this.options = config.options || {};
  this.emit = config.emit || (() => {}); // SSE emitter
  
  this.client = createHttpClient({
  timeout: config.timeout,
  userAgent: config.userAgent,
  });
  
  this.aborted = false;
  this.results = {
  paths: [],
  links: [],
  duplicates: [],
  sensitive: [],
  patterns: [],
  security: null,
  };
  this.stats = {
  total: 0,
  found: 0,
  redirects: 0,
  errors: 0,
  duplicates: 0,
  patterns: 0,
  };
  this.hashMap = {};
  }

abort() {
this.aborted = true;
}

log(msg, type = “info”) {
this.emit(“log”, { ts: timestamp(), msg, type });
}

async run() {
const isSource = !this.target.startsWith(“http”);

```
this.log(`[*] Target: ${isSource ? "Source Code Analysis" : this.target}`, "info");
this.log(`[*] Threads: ${this.threads}`, "info");
this.log(`[*] Options: ${Object.entries(this.options).filter(([, v]) => v).map(([k]) => k).join(", ")}`, "info");

try {
  // ── Phase 1: Fetch target & extract paths ──────────────────────
  if (isSource) {
    await this.analyzeSource(this.target);
  } else {
    await this.analyzeUrl(this.target);
  }

  if (this.aborted) return this.getResults();

  // ── Phase 2: Scan wordlist paths ───────────────────────────────
  if (!isSource && this.wordlist.length > 0) {
    await this.scanPaths(this.wordlist, "wordlist");
  }

  if (this.aborted) return this.getResults();

  // ── Phase 3: Scan sensitive files ──────────────────────────────
  if (!isSource && this.options.sensitive) {
    const sensitivePaths = SENSITIVE_FILES.map((f) => f.path);
    await this.scanPaths(sensitivePaths, "sensitive");
  }

  if (this.aborted) return this.getResults();

  // ── Phase 4: Security analysis ─────────────────────────────────
  if (!isSource && this.options.security) {
    await this.analyzeSecurityTarget();
  }

  // ── Phase 5: Compile duplicates ────────────────────────────────
  this.compileDuplicates();

  this.log("[✓] Scan complete!", "success");
  this.emit("complete", this.getResults());

} catch (err) {
  this.log(`[!] Fatal error: ${err.message}`, "error");
  this.emit("error", { message: err.message });
}

return this.getResults();
```

}

/**

- Analyze raw source code (HTML/JS)
  */
  async analyzeSource(source) {
  this.log(”[+] Extracting paths from source code…”, “action”);

```
const paths = extractPathsFromHTML(source, "");
const uniquePaths = [...new Set(paths)];

this.results.paths = uniquePaths.map((p, i) => ({
  id: i,
  path: p,
  source: "source_analysis",
  type: p.startsWith("http") ? "absolute" : "relative",
}));

this.log(`[✓] Extracted ${uniquePaths.length} unique paths`, "success");
this.emit("paths", this.results.paths);

// Run pattern detection on source
if (this.options.patterns) {
  this.log("[+] Running pattern detection on source...", "action");
  this.results.patterns = detectPatterns(source, "source_input");
  this.stats.patterns = this.results.patterns.length;

  if (this.results.patterns.length > 0) {
    this.log(`[✓] Found ${this.results.patterns.length} sensitive patterns`, "success");
    const crits = this.results.patterns.filter((p) => p.severity === "critical").length;
    if (crits > 0) {
      this.log(`[!] ${crits} CRITICAL patterns found!`, "error");
    }
  } else {
    this.log("[·] No sensitive patterns detected", "info");
  }
  this.emit("patterns", this.results.patterns);
}
```

}

/**

- Analyze a live URL
  */
  async analyzeUrl(url) {
  this.log(`[+] Fetching target: ${url}`, “action”);

```
const result = await requestWithRedirects(this.client, url);

if (result.error) {
  this.log(`[!] Failed to fetch target: ${result.error}`, "error");
  return;
}

this.log(`[✓] Target responded: ${result.status} (${(result.size / 1024).toFixed(1)} KB)`, "success");

if (result.chain.length > 0) {
  this.log(`[→] Redirect chain: ${result.chain.length} hops → ${result.finalUrl}`, "redirect");
}

// Extract paths from response
this.log("[+] Extracting paths from response...", "action");
const paths = extractPathsFromHTML(result.body, url);
const uniquePaths = [...new Set(paths)];

this.results.paths = uniquePaths.map((p, i) => ({
  id: i,
  path: p,
  source: "target_response",
  type: p.startsWith("http") ? "absolute" : "relative",
}));

this.log(`[✓] Extracted ${uniquePaths.length} unique paths from response`, "success");
this.emit("paths", this.results.paths);

// Detect patterns in response body
if (this.options.patterns) {
  this.log("[+] Running pattern detection on response...", "action");
  this.results.patterns = detectPatterns(result.body, url);
  this.stats.patterns = this.results.patterns.length;

  if (this.results.patterns.length > 0) {
    this.log(`[✓] Found ${this.results.patterns.length} patterns in response`, "success");
  }
  this.emit("patterns", this.results.patterns);
}
```

}

/**

- Scan a list of paths concurrently
  */
  async scanPaths(paths, type) {
  const baseUrl = this.target.replace(//+$/, “”);
  this.log(`[+] Scanning ${paths.length} ${type} paths (${this.threads} threads)...`, “action”);

```
const limit = pLimit(this.threads);
let completed = 0;
const total = paths.length;

const tasks = paths.map((path) =>
  limit(async () => {
    if (this.aborted) return;

    const fullUrl = normalizeUrl(baseUrl, path);
    if (!fullUrl) return;

    const result = await requestWithRedirects(this.client, fullUrl);
    completed++;

    const progress = Math.round((completed / total) * 100);
    this.stats.total = completed;

    if (result.error) {
      this.stats.errors++;
      if (completed % 10 === 0 || completed === total) {
        this.emit("progress", { progress, stats: { ...this.stats } });
      }
      return;
    }

    const entry = {
      id: this.results.links.length,
      url: fullUrl,
      path,
      status: result.status,
      size: result.size,
      contentType: result.contentType,
      redirectChain: result.chain,
      finalUrl: result.finalUrl,
      hash: result.hash,
      type,
    };

    // Track for duplicates
    if (!this.hashMap[result.hash]) {
      this.hashMap[result.hash] = [];
    }
    this.hashMap[result.hash].push(entry);

    // Categorize
    if (result.status >= 200 && result.status < 400) {
      this.stats.found++;
      this.results.links.push(entry);

      if (type === "sensitive") {
        const meta = SENSITIVE_FILES.find((f) => f.path === path);
        entry.category = meta?.category || "unknown";
        entry.fileSeverity = meta?.severity || "medium";
        this.results.sensitive.push(entry);
      }

      // Pattern detection on successful responses
      if (this.options.patterns && result.body && result.status === 200) {
        const patterns = detectPatterns(result.body, fullUrl);
        if (patterns.length > 0) {
          this.results.patterns.push(...patterns);
          this.stats.patterns += patterns.length;
        }
      }
    }

    if (result.chain.length > 0) {
      this.stats.redirects++;
    }
    if (result.status >= 400) {
      this.stats.errors++;
    }

    // Log notable findings
    const icon = result.status < 300 ? "✓" : result.status < 400 ? "→" : "✗";
    const logType = result.status < 300 ? "success" : result.status < 400 ? "redirect" : "muted";
    if (result.status < 400 || completed % 20 === 0) {
      this.log(
        `[${icon}] ${result.status} ${path} (${(result.size / 1024).toFixed(1)}KB) ${result.chain.length ? `→ ${result.finalUrl}` : ""}`,
        logType
      );
    }

    this.emit("progress", { progress, stats: { ...this.stats } });
  })
);

await Promise.all(tasks);

this.log(`[✓] ${type} scan done: ${this.stats.found} found, ${this.stats.errors} errors`, "success");
this.emit("links", this.results.links);
if (type === "sensitive") {
  this.emit("sensitive", this.results.sensitive);
}
```

}

/**

- Run security analysis on the target
  */
  async analyzeSecurityTarget() {
  this.log(”[+] Analyzing security headers…”, “action”);

```
try {
  const response = await this.client.get(this.target);
  const headers = response.headers;

  // Analyze security headers
  const headerAnalysis = analyzeSecurityHeaders(headers);

  // Analyze cookies
  const setCookies = headers["set-cookie"];
  const cookieAnalysis = analyzeCookies(setCookies);

  // Test allowed methods
  this.log("[+] Testing allowed HTTP methods...", "action");
  const methods = await testAllowedMethods(this.target, this.client);

  this.results.security = {
    headers: headerAnalysis.headers,
    infoLeaks: headerAnalysis.infoLeaks,
    cookies: cookieAnalysis,
    methods,
    score: headerAnalysis.score,
    grade: headerAnalysis.grade,
  };

  const missing = headerAnalysis.headers.filter((h) => !h.present).length;
  this.log(
    `[✓] Security Grade: ${headerAnalysis.grade} (${headerAnalysis.score}%) — ${missing} missing headers`,
    missing > 5 ? "error" : missing > 2 ? "redirect" : "success"
  );

  if (headerAnalysis.infoLeaks.length > 0) {
    this.log(
      `[!] ${headerAnalysis.infoLeaks.length} information disclosure headers found`,
      "error"
    );
  }

  if (cookieAnalysis.some((c) => !c.safe)) {
    this.log("[!] Insecure cookie configuration detected", "error");
  }

  const dangerous = methods.filter((m) => m.dangerous);
  if (dangerous.length > 0) {
    this.log(
      `[!] Dangerous methods enabled: ${dangerous.map((m) => m.method).join(", ")}`,
      "error"
    );
  }

  this.emit("security", this.results.security);
} catch (err) {
  this.log(`[!] Security analysis failed: ${err.message}`, "error");
}
```

}

/**

- Compile duplicate responses
  */
  compileDuplicates() {
  Object.entries(this.hashMap).forEach(([hash, entries]) => {
  if (entries.length > 1) {
  this.results.duplicates.push({
  hash,
  urls: entries.map((e) => e.url),
  count: entries.length,
  status: entries[0].status,
  size: entries[0].size,
  contentType: entries[0].contentType,
  });
  }
  });
  this.stats.duplicates = this.results.duplicates.length;

```
if (this.results.duplicates.length > 0) {
  this.log(`[✓] ${this.results.duplicates.length} duplicate response groups detected`, "success");
}
this.emit("duplicates", this.results.duplicates);
```

}

getResults() {
return {
target: this.target,
results: this.results,
stats: this.stats,
timestamp: new Date().toISOString(),
};
}
}

module.exports = { Scanner, requestWithRedirects, createHttpClient };
