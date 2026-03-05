// ─── Security Headers to Check ───────────────────────────────────────────────

const SECURITY_HEADERS = [
{
name: “Content-Security-Policy”,
severity: “high”,
desc: “Prevents XSS, clickjacking, and code injection”,
recommendation: “Set a strict CSP that limits script-src, style-src, and other directives”,
},
{
name: “X-Frame-Options”,
severity: “high”,
desc: “Prevents clickjacking attacks”,
recommendation: “Set to DENY or SAMEORIGIN”,
},
{
name: “X-Content-Type-Options”,
severity: “medium”,
desc: “Prevents MIME type sniffing”,
recommendation: “Set to nosniff”,
},
{
name: “Strict-Transport-Security”,
severity: “high”,
desc: “Forces HTTPS connections”,
recommendation: “Set max-age to at least 31536000 with includeSubDomains”,
},
{
name: “X-XSS-Protection”,
severity: “low”,
desc: “Legacy XSS filter (use CSP instead)”,
recommendation: “Set to 0 (disabled) if CSP is present, or 1; mode=block”,
},
{
name: “Referrer-Policy”,
severity: “medium”,
desc: “Controls referrer information leakage”,
recommendation: “Set to strict-origin-when-cross-origin or no-referrer”,
},
{
name: “Permissions-Policy”,
severity: “medium”,
desc: “Controls browser feature access”,
recommendation: “Restrict camera, microphone, geolocation, etc.”,
},
{
name: “Cross-Origin-Opener-Policy”,
severity: “medium”,
desc: “Isolates browsing context”,
recommendation: “Set to same-origin”,
},
{
name: “Cross-Origin-Resource-Policy”,
severity: “medium”,
desc: “Prevents cross-origin resource loading”,
recommendation: “Set to same-origin or same-site”,
},
{
name: “Cross-Origin-Embedder-Policy”,
severity: “medium”,
desc: “Requires CORS for cross-origin resources”,
recommendation: “Set to require-corp”,
},
{
name: “X-Permitted-Cross-Domain-Policies”,
severity: “low”,
desc: “Controls Flash and PDF cross-domain access”,
recommendation: “Set to none”,
},
{
name: “X-Download-Options”,
severity: “low”,
desc: “Prevents IE from opening downloaded files”,
recommendation: “Set to noopen”,
},
{
name: “Cache-Control”,
severity: “medium”,
desc: “Controls response caching”,
recommendation: “Set no-store for sensitive pages”,
},
{
name: “Pragma”,
severity: “low”,
desc: “Legacy cache control”,
recommendation: “Set to no-cache for sensitive pages”,
},
];

// ─── Information Disclosure Headers ──────────────────────────────────────────

const INFO_LEAK_HEADERS = [
“Server”,
“X-Powered-By”,
“X-AspNet-Version”,
“X-AspNetMvc-Version”,
“X-Generator”,
“X-Drupal-Cache”,
“X-Runtime”,
“X-Version”,
“X-Backend-Server”,
“Via”,
];

// ─── Cookie Security Flags ───────────────────────────────────────────────────

function analyzeCookies(setCookieHeaders) {
if (!setCookieHeaders) return [];
const cookies = Array.isArray(setCookieHeaders)
? setCookieHeaders
: [setCookieHeaders];

return cookies.map((raw) => {
const parts = raw.split(”;”).map((p) => p.trim());
const [nameVal, …flags] = parts;
const [name] = nameVal.split(”=”);
const flagNames = flags.map((f) => f.split(”=”)[0].toLowerCase().trim());

```
const issues = [];
const hasSecure = flagNames.includes("secure");
const hasHttpOnly = flagNames.includes("httponly");
const hasSameSite = flagNames.some((f) => f === "samesite");
const sameSiteValue = flags
  .find((f) => f.toLowerCase().startsWith("samesite"))
  ?.split("=")[1]
  ?.trim()
  ?.toLowerCase();

if (!hasSecure) issues.push("Missing Secure flag");
if (!hasHttpOnly) issues.push("Missing HttpOnly flag");
if (!hasSameSite) issues.push("Missing SameSite attribute");
if (sameSiteValue === "none" && !hasSecure)
  issues.push("SameSite=None without Secure");

return {
  name: name?.trim(),
  raw,
  flags: flags.map((f) => f.trim()),
  secure: hasSecure,
  httpOnly: hasHttpOnly,
  sameSite: sameSiteValue || "not set",
  issues,
  safe: issues.length === 0,
};
```

});
}

// ─── Full Security Analysis ──────────────────────────────────────────────────

function analyzeSecurityHeaders(headers) {
const result = {
headers: [],
infoLeaks: [],
score: 0,
grade: “F”,
};

// Check security headers
let found = 0;
SECURITY_HEADERS.forEach((sh) => {
const headerName = Object.keys(headers).find(
(h) => h.toLowerCase() === sh.name.toLowerCase()
);
const present = !!headerName;
const value = present ? headers[headerName] : null;

```
if (present) found++;

result.headers.push({
  header: sh.name,
  desc: sh.desc,
  severity: sh.severity,
  present,
  value: value || "MISSING",
  recommendation: present ? null : sh.recommendation,
});
```

});

// Check info leak headers
INFO_LEAK_HEADERS.forEach((name) => {
const headerName = Object.keys(headers).find(
(h) => h.toLowerCase() === name.toLowerCase()
);
if (headerName) {
result.infoLeaks.push({
header: name,
value: headers[headerName],
severity: “info”,
recommendation: `Remove or mask the ${name} header to prevent information disclosure`,
});
}
});

// Score
const total = SECURITY_HEADERS.length;
result.score = Math.round((found / total) * 100);
if (result.score >= 90) result.grade = “A+”;
else if (result.score >= 80) result.grade = “A”;
else if (result.score >= 70) result.grade = “B”;
else if (result.score >= 60) result.grade = “C”;
else if (result.score >= 40) result.grade = “D”;
else result.grade = “F”;

return result;
}

/**

- Test allowed HTTP methods
  */
  async function testAllowedMethods(url, axiosInstance) {
  const methods = [“GET”, “POST”, “PUT”, “DELETE”, “PATCH”, “OPTIONS”, “HEAD”, “TRACE”];
  const allowed = [];

for (const method of methods) {
try {
const res = await axiosInstance({
method: method.toLowerCase(),
url,
timeout: 5000,
maxRedirects: 0,
validateStatus: () => true,
});
// If not 405 Method Not Allowed, consider it allowed
if (res.status !== 405 && res.status !== 501) {
allowed.push({
method,
status: res.status,
dangerous: [“TRACE”, “PUT”, “DELETE”].includes(method),
});
}
} catch {
// Skip errors
}
}

return allowed;
}

module.exports = {
SECURITY_HEADERS,
analyzeSecurityHeaders,
analyzeCookies,
testAllowedMethods,
};
