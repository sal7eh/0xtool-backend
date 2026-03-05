const cheerio = require(“cheerio”);

// ─── Path Extraction Patterns ────────────────────────────────────────────────

const JS_PATH_PATTERNS = [
// fetch / axios / XMLHttpRequest
/fetch\s*(\s*[”’`]([^"'`\s]+?)[”’`]/g, /axios\.(?:get|post|put|delete|patch|head|options|request)\s*\(\s*["'`]([^"'`\s]+?)[”’`]/g, /\.(?:open|send)\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[”’`]\s*,\s*["'`]([^"'`\s]+?)[”’`]/g,

// URL assignments
/(?:url|path|endpoint|route|api|href|src|action|redirect|next|return_url|callback|goto|link|uri)\s*[:=]\s*[”’`]([^"'`\s]{2,})[”’`]/gi,

// window.location / window.open
/window.location(?:.href)?\s*=\s*[”’`]([^"'`\s]+?)[”’`]/g, /window\.open\s*\(\s*["'`]([^"'`\s]+?)[”’`]/g,

// Relative paths in strings
/[”’`](\/[a-zA-Z0-9_\-./]+(?:\?[^"'`]*)?)[”’`]/g,

// Template literals with paths
/`(\/[a-zA-Z0-9_\-./\$\{]+(?:\?[^`]*)?)`/g,

// Full URLs in strings
/[”’`](https?:\/\/[^\s"'`<>()]{5,})[”’`]/gi,

// Source map references
///[#@]\s*sourceMappingURL=(.+)/g,

// importScripts
/importScripts\s*(\s*[”’`]([^"'`]+?)[”’`]/g,

// Router definitions (React Router, Vue Router, Express)
/path\s*:\s*[”’`](\/[^"'`]+)[”’`]/g,

// API base / prefix
/(?:baseURL|apiUrl|API_URL|API_BASE|BASE_URL|prefix)\s*[:=]\s*[”’`]([^"'`\s]+)[”’`]/gi,
];

const HTML_ATTRIBUTES = [
“href”,
“src”,
“action”,
“data-url”,
“data-src”,
“data-href”,
“data-api”,
“data-endpoint”,
“data-action”,
“poster”,
“formaction”,
“cite”,
“background”,
“srcset”,
“lowsrc”,
“dynsrc”,
];

// ─── Sensitive Patterns ──────────────────────────────────────────────────────

const SENSITIVE_PATTERNS = {
// Cloud & API Keys
aws_access_key: {
regex: /AKIA[0-9A-Z]{16}/g,
label: “AWS Access Key ID”,
severity: “critical”,
},
aws_secret_key: {
regex: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*[”’]?([A-Za-z0-9/+=]{40})[”’]?/gi,
label: “AWS Secret Key”,
severity: “critical”,
},
aws_s3_bucket: {
regex: /[a-zA-Z0-9.*-]+.s3(?:.[a-z0-9-]+)?.amazonaws.com|s3://[a-zA-Z0-9.*-]+/g,
label: “AWS S3 Bucket”,
severity: “high”,
},
aws_arn: {
regex: /arn:aws:[a-zA-Z0-9-]+:[a-z0-9-]*:\d{12}:[^\s”’]+/g,
label: “AWS ARN”,
severity: “medium”,
},
google_api_key: {
regex: /AIza[0-9A-Za-z-*]{35}/g,
label: “Google API Key”,
severity: “critical”,
},
google_oauth: {
regex: /[0-9]+-[0-9A-Za-z*]{32}.apps.googleusercontent.com/g,
label: “Google OAuth Client ID”,
severity: “high”,
},
google_cloud: {
regex: /[a-z0-9-]+.cloudfunctions.net|[a-z0-9-]+.appspot.com/g,
label: “Google Cloud Endpoint”,
severity: “medium”,
},
azure_key: {
regex: /(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{44,88})/g,
label: “Azure Storage Key”,
severity: “critical”,
},

// Tokens
jwt_token: {
regex: /eyJ[A-Za-z0-9_-]*.eyJ[A-Za-z0-9_-]*.[A-Za-z0-9_-]*/g,
label: “JWT Token”,
severity: “critical”,
},
bearer_token: {
regex: /Bearer\s+[A-Za-z0-9-._~+/]+=*/g,
label: “Bearer Token”,
severity: “critical”,
},
github_token: {
regex: /gh[pousr]*[A-Za-z0-9*]{36,}/g,
label: “GitHub Token”,
severity: “critical”,
},
slack_token: {
regex: /xox[bpors]-[0-9]{10,13}-[0-9A-Za-z-]{24,}/g,
label: “Slack Token”,
severity: “critical”,
},
stripe_key: {
regex: /(?:sk|pk)*(?:live|test)*[0-9a-zA-Z]{24,}/g,
label: “Stripe API Key”,
severity: “critical”,
},
twilio_key: {
regex: /SK[0-9a-fA-F]{32}/g,
label: “Twilio API Key”,
severity: “high”,
},
sendgrid_key: {
regex: /SG.[A-Za-z0-9_-]{22}.[A-Za-z0-9_-]{43}/g,
label: “SendGrid API Key”,
severity: “critical”,
},
mailgun_key: {
regex: /key-[0-9a-zA-Z]{32}/g,
label: “Mailgun API Key”,
severity: “critical”,
},

// Private Keys
private_key: {
regex: /—–BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\s?BLOCK)?—–/g,
label: “Private Key”,
severity: “critical”,
},

// Database
database_url: {
regex: /(?:mongodb|postgres|mysql|redis|amqp|memcached)://[^\s”’<>]+/gi,
label: “Database Connection String”,
severity: “critical”,
},

// PII & Contact
email_address: {
regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}/g,
label: “Email Address”,
severity: “info”,
},
phone_number: {
regex: /(?:+\d{1,3}[-.\s]?)?(?\d{3})?[-.\s]?\d{3}[-.\s]?\d{4}/g,
label: “Phone Number”,
severity: “low”,
},
ip_address: {
regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?).){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
label: “IP Address”,
severity: “medium”,
},
ipv6_address: {
regex: /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/g,
label: “IPv6 Address”,
severity: “medium”,
},

// Infrastructure
firebase_url: {
regex: /[a-z0-9-]+.firebaseio.com|[a-z0-9-]+.firebaseapp.com/g,
label: “Firebase URL”,
severity: “medium”,
},
heroku_api: {
regex: /https?://api.heroku.com/[^\s”’]+/g,
label: “Heroku API Endpoint”,
severity: “medium”,
},
internal_url: {
regex: /https?://(?:localhost|127.0.0.1|10.\d+.\d+.\d+|172.(?:1[6-9]|2\d|3[01]).\d+.\d+|192.168.\d+.\d+)(?::\d+)?[^\s”’]*/g,
label: “Internal/Private URL”,
severity: “high”,
},

// Misc Secrets
password_field: {
regex: /(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*[”’]([^"'\s]{4,})[”’]/gi,
label: “Hardcoded Password/Secret”,
severity: “critical”,
},
};

// ─── Sensitive File Paths ────────────────────────────────────────────────────

const SENSITIVE_FILES = [
// Environment & Config
{ path: “/.env”, category: “config”, severity: “critical” },
{ path: “/.env.local”, category: “config”, severity: “critical” },
{ path: “/.env.production”, category: “config”, severity: “critical” },
{ path: “/.env.staging”, category: “config”, severity: “critical” },
{ path: “/.env.development”, category: “config”, severity: “critical” },
{ path: “/.env.backup”, category: “config”, severity: “critical” },
{ path: “/config.php”, category: “config”, severity: “high” },
{ path: “/config.yml”, category: “config”, severity: “high” },
{ path: “/config.json”, category: “config”, severity: “high” },
{ path: “/wp-config.php”, category: “config”, severity: “critical” },
{ path: “/wp-config.php.bak”, category: “config”, severity: “critical” },
{ path: “/web.config”, category: “config”, severity: “high” },
{ path: “/application.yml”, category: “config”, severity: “high” },
{ path: “/application.properties”, category: “config”, severity: “high” },
{ path: “/settings.py”, category: “config”, severity: “high” },
{ path: “/.npmrc”, category: “config”, severity: “high” },
{ path: “/.yarnrc”, category: “config”, severity: “medium” },

// Version Control
{ path: “/.git/config”, category: “vcs”, severity: “high” },
{ path: “/.git/HEAD”, category: “vcs”, severity: “high” },
{ path: “/.git/logs/HEAD”, category: “vcs”, severity: “high” },
{ path: “/.gitignore”, category: “vcs”, severity: “low” },
{ path: “/.svn/entries”, category: “vcs”, severity: “high” },
{ path: “/.svn/wc.db”, category: “vcs”, severity: “high” },
{ path: “/.hg/hgrc”, category: “vcs”, severity: “high” },

// Backups & Dumps
{ path: “/backup.zip”, category: “backup”, severity: “critical” },
{ path: “/backup.tar.gz”, category: “backup”, severity: “critical” },
{ path: “/backup.sql”, category: “backup”, severity: “critical” },
{ path: “/database.sql”, category: “backup”, severity: “critical” },
{ path: “/db.sql”, category: “backup”, severity: “critical” },
{ path: “/dump.sql”, category: “backup”, severity: “critical” },
{ path: “/data.sql”, category: “backup”, severity: “critical” },
{ path: “/site.tar.gz”, category: “backup”, severity: “critical” },
{ path: “/www.zip”, category: “backup”, severity: “critical” },
{ path: “/htdocs.zip”, category: “backup”, severity: “critical” },

// Server Config
{ path: “/.htaccess”, category: “server”, severity: “medium” },
{ path: “/.htpasswd”, category: “server”, severity: “critical” },
{ path: “/server-status”, category: “server”, severity: “high” },
{ path: “/server-info”, category: “server”, severity: “high” },
{ path: “/nginx.conf”, category: “server”, severity: “high” },
{ path: “/Dockerfile”, category: “server”, severity: “medium” },
{ path: “/docker-compose.yml”, category: “server”, severity: “high” },
{ path: “/docker-compose.yaml”, category: “server”, severity: “high” },

// Debug & Info
{ path: “/phpinfo.php”, category: “debug”, severity: “high” },
{ path: “/info.php”, category: “debug”, severity: “high” },
{ path: “/debug”, category: “debug”, severity: “high” },
{ path: “/debug/default/view”, category: “debug”, severity: “high” },
{ path: “/_profiler”, category: “debug”, severity: “high” },
{ path: “/elmah.axd”, category: “debug”, severity: “high” },
{ path: “/trace.axd”, category: “debug”, severity: “high” },
{ path: “/actuator”, category: “debug”, severity: “high” },
{ path: “/actuator/health”, category: “debug”, severity: “medium” },
{ path: “/actuator/env”, category: “debug”, severity: “critical” },
{ path: “/actuator/configprops”, category: “debug”, severity: “critical” },
{ path: “/actuator/heapdump”, category: “debug”, severity: “critical” },
{ path: “/actuator/mappings”, category: “debug”, severity: “high” },
{ path: “/metrics”, category: “debug”, severity: “medium” },
{ path: “/**debug**”, category: “debug”, severity: “high” },

// API Documentation
{ path: “/swagger.json”, category: “api”, severity: “medium” },
{ path: “/swagger.yaml”, category: “api”, severity: “medium” },
{ path: “/swagger-ui.html”, category: “api”, severity: “medium” },
{ path: “/api-docs”, category: “api”, severity: “medium” },
{ path: “/v1/api-docs”, category: “api”, severity: “medium” },
{ path: “/v2/api-docs”, category: “api”, severity: “medium” },
{ path: “/openapi.json”, category: “api”, severity: “medium” },
{ path: “/graphql”, category: “api”, severity: “medium” },
{ path: “/graphiql”, category: “api”, severity: “medium” },
{ path: “/.well-known/openid-configuration”, category: “api”, severity: “medium” },

// Admin Panels
{ path: “/admin”, category: “admin”, severity: “high” },
{ path: “/admin/login”, category: “admin”, severity: “high” },
{ path: “/administrator”, category: “admin”, severity: “high” },
{ path: “/wp-admin”, category: “admin”, severity: “high” },
{ path: “/wp-login.php”, category: “admin”, severity: “high” },
{ path: “/cpanel”, category: “admin”, severity: “high” },
{ path: “/phpmyadmin”, category: “admin”, severity: “high” },
{ path: “/adminer.php”, category: “admin”, severity: “critical” },

// Well-Known & Meta
{ path: “/robots.txt”, category: “meta”, severity: “low” },
{ path: “/sitemap.xml”, category: “meta”, severity: “low” },
{ path: “/.well-known/security.txt”, category: “meta”, severity: “low” },
{ path: “/crossdomain.xml”, category: “meta”, severity: “medium” },
{ path: “/clientaccesspolicy.xml”, category: “meta”, severity: “medium” },
{ path: “/humans.txt”, category: “meta”, severity: “low” },
{ path: “/.well-known/assetlinks.json”, category: “meta”, severity: “low” },

// Package Managers
{ path: “/package.json”, category: “deps”, severity: “low” },
{ path: “/package-lock.json”, category: “deps”, severity: “low” },
{ path: “/yarn.lock”, category: “deps”, severity: “low” },
{ path: “/composer.json”, category: “deps”, severity: “low” },
{ path: “/composer.lock”, category: “deps”, severity: “low” },
{ path: “/Gemfile”, category: “deps”, severity: “low” },
{ path: “/Gemfile.lock”, category: “deps”, severity: “low” },
{ path: “/requirements.txt”, category: “deps”, severity: “low” },
{ path: “/Pipfile”, category: “deps”, severity: “low” },
{ path: “/go.mod”, category: “deps”, severity: “low” },

// Cloud
{ path: “/.aws/credentials”, category: “cloud”, severity: “critical” },
{ path: “/.aws/config”, category: “cloud”, severity: “high” },
{ path: “/.gcloud/credentials.json”, category: “cloud”, severity: “critical” },
{ path: “/firebase.json”, category: “cloud”, severity: “medium” },
{ path: “/.firebaserc”, category: “cloud”, severity: “medium” },

// System
{ path: “/.DS_Store”, category: “system”, severity: “low” },
{ path: “/Thumbs.db”, category: “system”, severity: “low” },
{ path: “/WEB-INF/web.xml”, category: “system”, severity: “high” },
{ path: “/META-INF/MANIFEST.MF”, category: “system”, severity: “medium” },
];

// ─── Functions ───────────────────────────────────────────────────────────────

/**

- Extract paths from HTML content using Cheerio
  */
  function extractPathsFromHTML(html, baseUrl) {
  const paths = new Set();
  try {
  const $ = cheerio.load(html);
  
  // Extract from HTML attributes
  HTML_ATTRIBUTES.forEach((attr) => {
  $(`[${attr}]`).each((_, el) => {
  let val = $(el).attr(attr);
  if (val) {
  // Handle srcset
  if (attr === “srcset”) {
  val.split(”,”).forEach((part) => {
  const url = part.trim().split(/\s+/)[0];
  if (url) paths.add(url);
  });
  } else {
  paths.add(val.trim());
  }
  }
  });
  });
  
  // Extract from inline scripts
  $(“script”).each((_, el) => {
  const content = $(el).html();
  if (content) {
  extractPathsFromJS(content).forEach((p) => paths.add(p));
  }
  });
  
  // Extract from style tags (url() references)
  $(“style”).each((_, el) => {
  const content = $(el).html();
  if (content) {
  const urlPattern = /url\s*(\s*[”’]?([^”’)]+)[”’]?\s*)/g;
  let m;
  while ((m = urlPattern.exec(content)) !== null) {
  paths.add(m[1].trim());
  }
  }
  });
  
  // Extract from inline styles
  $(”[style]”).each((_, el) => {
  const style = $(el).attr(“style”);
  if (style) {
  const urlPattern = /url\s*(\s*[”’]?([^”’)]+)[”’]?\s*)/g;
  let m;
  while ((m = urlPattern.exec(style)) !== null) {
  paths.add(m[1].trim());
  }
  }
  });
  
  // Comments may contain paths
  const commentPattern = /<!--([\s\S]*?)-->/g;
  let cm;
  while ((cm = commentPattern.exec(html)) !== null) {
  extractPathsFromJS(cm[1]).forEach((p) => paths.add(p));
  }
  } catch (err) {
  // Fallback: treat as JS
  extractPathsFromJS(html).forEach((p) => paths.add(p));
  }

return filterPaths([…paths], baseUrl);
}

/**

- Extract paths from JS content using regex patterns
  */
  function extractPathsFromJS(js) {
  const paths = new Set();
  JS_PATH_PATTERNS.forEach((pattern) => {
  const regex = new RegExp(pattern.source, pattern.flags);
  let match;
  while ((match = regex.exec(js)) !== null) {
  const val = match[1]?.trim();
  if (val) paths.add(val);
  }
  });
  return […paths];
  }

/**

- Filter extracted paths (remove junk)
  */
  function filterPaths(paths, baseUrl) {
  const domain = baseUrl ? (() => { try { return new URL(baseUrl).hostname; } catch { return “”; } })() : “”;

return paths
.filter((p) => {
if (!p || p.length < 2) return false;
if (p.startsWith(“data:”)) return false;
if (p.startsWith(“javascript:”)) return false;
if (p.startsWith(“mailto:”)) return false;
if (p.startsWith(“tel:”)) return false;
if (p.startsWith(”#”)) return false;
if (p.startsWith(“blob:”)) return false;
if (p === “/”) return false;
if (/^\s+$/.test(p)) return false;
// Skip obvious non-paths
if (/^[{([]/.test(p)) return false;
return true;
})
.map((p) => {
// Clean up
p = p.replace(/[’”`;,\s]+$/, "").replace(/^['"`;,\s]+/, “”);
return p;
})
.filter((p) => p.length >= 2);
}

/**

- Detect sensitive patterns in content
  */
  function detectPatterns(content, sourceUrl) {
  const results = [];
  const seen = new Set();

Object.entries(SENSITIVE_PATTERNS).forEach(([key, { regex, label, severity }]) => {
const re = new RegExp(regex.source, regex.flags);
let match;
while ((match = re.exec(content)) !== null) {
const value = match[1] || match[0];
const truncated = value.substring(0, 100);
const dedupKey = `${key}:${truncated}`;

```
  if (!seen.has(dedupKey)) {
    seen.add(dedupKey);

    // Get surrounding context (30 chars each side)
    const start = Math.max(0, match.index - 30);
    const end = Math.min(content.length, match.index + match[0].length + 30);
    const context = content.substring(start, end).replace(/\n/g, " ");

    results.push({
      id: `${key}-${match.index}`,
      pattern: label,
      patternKey: key,
      match: truncated,
      context: context,
      severity,
      location: sourceUrl || `offset:${match.index}`,
      offset: match.index,
    });
  }
}
```

});

// Sort by severity
const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
results.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));

return results;
}

module.exports = {
extractPathsFromHTML,
extractPathsFromJS,
detectPatterns,
SENSITIVE_FILES,
SENSITIVE_PATTERNS,
};
