const crypto = require("crypto");

function hashBody(body) {
  return crypto.createHash("sha256").update(body).digest("hex").substring(0, 16);
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function normalizeUrl(base, path) {
  try {
    if (path.startsWith("http://") || path.startsWith("https://")) {
      return new URL(path).href;
    }
    const baseUrl = base.endsWith("/") ? base.slice(0, -1) : base;
    const cleanPath = path.startsWith("/") ? path : "/" + path;
    return new URL(cleanPath, baseUrl).href;
  } catch {
    return null;
  }
}

function isValidUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function timestamp() {
  return new Date().toISOString().replace("T", " ").substring(0, 19);
}

module.exports = {
  hashBody,
  formatBytes,
  normalizeUrl,
  isValidUrl,
  getDomain,
  sleep,
  timestamp,
};
