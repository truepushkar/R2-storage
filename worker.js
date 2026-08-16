const VERSION = "3.0.0";
const BUCKET_NAME = "api";
const COOKIE_NAME = "session";

const EXPIRATIONS = {
  "1h": 60 * 60,
  "6h": 6 * 60 * 60,
  "12h": 12 * 60 * 60,
  "1d": 24 * 60 * 60,
  "3d": 3 * 24 * 60 * 60,
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
  "never": null,
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, Range",
  "Access-Control-Expose-Headers":
    "Content-Length, Content-Range, Content-Type, ETag, Accept-Ranges",
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

/* ============================================================
   MAIN
   ============================================================ */

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
        });
      }

      if (request.method === "GET" && url.pathname === "/") {
        return publicPage();
      }

      if (request.method === "GET" && url.pathname === "/docs") {
        return docsPage();
      }

      if (request.method === "POST" && url.pathname === "/auth/login") {
        return await login(request, env);
      }

      if (request.method === "POST" && url.pathname === "/auth/logout") {
        return logout();
      }

      if (request.method === "GET" && url.pathname === "/dashboard") {
        if (!isAuthenticated(request, env)) {
          return Response.redirect(`${url.origin}/`, 302);
        }
        return dashboardPage();
      }

      if (url.pathname.startsWith("/api/")) {
        if (!isAuthenticated(request, env)) {
          return json(
            {
              error: {
                message: "Unauthorized",
                type: "authentication_error",
              },
            },
            401,
            { "WWW-Authenticate": 'Bearer realm="Content Delivery"' }
          );
        }
        return await handleAPI(request, env, ctx, url);
      }

      if (request.method === "GET") {
        return notFoundPage();
      }

      return json({ error: { message: "Not found" } }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: { message: "Internal server error" } }, 500);
    }
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(cleanupExpiredFiles(env));
  },
};

/* ============================================================
   AUTHENTICATION
   ============================================================ */

function getApiKey(env) {
  return String(env.API_KEY || "");
}

function isAuthenticated(request, env) {
  const apiKey = getApiKey(env);

  if (!apiKey) {
    console.error("API_KEY is not configured.");
    return false;
  }

  const authorization = request.headers.get("Authorization");

  if (authorization) {
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (match && safeEqual(match[1], apiKey)) {
      return true;
    }
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");

  if (cookies[COOKIE_NAME] && safeEqual(cookies[COOKIE_NAME], apiKey)) {
    return true;
  }

  return false;
}

async function login(request, env) {
  const apiKey = getApiKey(env);

  if (!apiKey) {
    return json(
      { error: { message: "API_KEY is not configured in the Worker." } },
      500
    );
  }

  let token = "";
  const contentType = request.headers.get("Content-Type") || "";

  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const body = await request.json();
      token = String(body.token || "").trim();
    } catch {
      return json({ error: { message: "Invalid JSON." } }, 400);
    }
  } else {
    token = (await request.text()).trim();
  }

  if (!token || !safeEqual(token, apiKey)) {
    return json({ error: { message: "Invalid API key." } }, 401);
  }

  const cookie = [
    `${COOKIE_NAME}=${encodeURIComponent(apiKey)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=604800",
  ].join("; ");

  return new Response(
    JSON.stringify({ authenticated: true, redirect: "/dashboard" }),
    {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        ...SECURITY_HEADERS,
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie": cookie,
      },
    }
  );
}

function logout() {
  const cookie = [
    `${COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0",
  ].join("; ");

  return new Response(JSON.stringify({ authenticated: false }), {
    status: 200,
    headers: {
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": cookie,
    },
  });
}

function parseCookies(header) {
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  }

  return cookies;
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/* ============================================================
   API ROUTER
   ============================================================ */

async function handleAPI(request, env, ctx, url) {
  const path = url.pathname;

  if (path === "/api/health" && request.method === "GET") {
    return json({
      object: "health",
      status: "ok",
      service: "Content Delivery",
      version: VERSION,
      bucket: BUCKET_NAME,
      timestamp: new Date().toISOString(),
    });
  }

  if (path === "/api/stats" && request.method === "GET") {
    return await getStats(env);
  }

  if (path === "/api/files" && request.method === "GET") {
    return await listFiles(env, url);
  }

  if (path === "/api/upload" && request.method === "PUT") {
    return await uploadRaw(request, env, url);
  }

  if (path === "/api/upload" && request.method === "POST") {
    return await uploadMultipart(request, env, url);
  }

  if (path === "/api/files" && request.method === "DELETE") {
    return await bulkDelete(request, env);
  }

  if (path.startsWith("/api/files/")) {
    const id = decodeURIComponent(path.slice("/api/files/".length));

    if (!id || id.includes("/") || id.includes("\\")) {
      return json({ error: { message: "Invalid file ID." } }, 400);
    }

    if (request.method === "GET") return await downloadFile(request, env, id);
    if (request.method === "HEAD") return await headFile(env, id);
    if (request.method === "DELETE") return await deleteFile(env, id);
  }

  return json({ error: { message: "API endpoint not found." } }, 404);
}

/* ============================================================
   RAW UPLOAD
   ============================================================ */

async function uploadRaw(request, env, url) {
  if (!request.body) {
    return json({ error: { message: "Request body is empty." } }, 400);
  }

  const filename = sanitizeFilename(
    url.searchParams.get("filename") ||
      request.headers.get("X-Filename") ||
      "file"
  );

  const expiry = url.searchParams.get("expires") || "7d";

  if (!Object.prototype.hasOwnProperty.call(EXPIRATIONS, expiry)) {
    return json(
      {
        error: {
          message: "Invalid expiration.",
          allowed: Object.keys(EXPIRATIONS),
        },
      },
      400
    );
  }

  const expirySeconds = EXPIRATIONS[expiry];
  const id = generateId();
  const key = `files/${id}`;
  const uploadedAt = Date.now();
  const expiresAt =
    expirySeconds === null ? null : uploadedAt + expirySeconds * 1000;

  const contentType =
    request.headers.get("Content-Type") || "application/octet-stream";
  const contentLength = request.headers.get("Content-Length");

  const metadata = {
    originalName: filename,
    contentType: contentType,
    size: contentLength || "0",
    uploadedAt: String(uploadedAt),
    expiresAt: expiresAt === null ? "never" : String(expiresAt),
  };

  /* Streams directly into R2 — no buffering, no size cap. */

  await env.BUCKET.put(key, request.body, {
    httpMetadata: {
      contentType,
      contentDisposition: buildContentDisposition(filename),
      cacheControl: "private, max-age=3600",
    },
    customMetadata: metadata,
  });

  return json(
    {
      object: "file",
      status: "complete",
      id,
      key,
      name: filename,
      size: contentLength ? Number(contentLength) : null,
      content_type: contentType,
      uploaded_at: new Date(uploadedAt).toISOString(),
      expires_at: expiresAt === null ? null : new Date(expiresAt).toISOString(),
      download_url: `${url.origin}/api/files/${encodeURIComponent(id)}`,
    },
    201
  );
}

/* ============================================================
   MULTIPART
   ============================================================ */

async function uploadMultipart(request, env, url) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("multipart/form-data")) {
    return json(
      { error: { message: "POST /api/upload requires multipart/form-data." } },
      400
    );
  }

  const form = await request.formData();
  const file = form.get("file");

  if (!(file instanceof File)) {
    return json({ error: { message: 'Missing "file" field.' } }, 400);
  }

  const expiry =
    url.searchParams.get("expires") || String(form.get("expires") || "7d");

  if (!Object.prototype.hasOwnProperty.call(EXPIRATIONS, expiry)) {
    return json(
      {
        error: {
          message: "Invalid expiration.",
          allowed: Object.keys(EXPIRATIONS),
        },
      },
      400
    );
  }

  const expirySeconds = EXPIRATIONS[expiry];
  const id = generateId();
  const key = `files/${id}`;
  const uploadedAt = Date.now();
  const expiresAt =
    expirySeconds === null ? null : uploadedAt + expirySeconds * 1000;

  const filename = sanitizeFilename(file.name || "file");
  const fileType = file.type || "application/octet-stream";

  await env.BUCKET.put(key, file.stream(), {
    httpMetadata: {
      contentType: fileType,
      contentDisposition: buildContentDisposition(filename),
      cacheControl: "private, max-age=3600",
    },
    customMetadata: {
      originalName: filename,
      contentType: fileType,
      size: String(file.size),
      uploadedAt: String(uploadedAt),
      expiresAt: expiresAt === null ? "never" : String(expiresAt),
    },
  });

  return json(
    {
      object: "file",
      status: "complete",
      id,
      key,
      name: filename,
      size: file.size,
      content_type: fileType,
      uploaded_at: new Date(uploadedAt).toISOString(),
      expires_at: expiresAt === null ? null : new Date(expiresAt).toISOString(),
      download_url: `${url.origin}/api/files/${encodeURIComponent(id)}`,
    },
    201
  );
}

/* ============================================================
   LIST
   ============================================================ */

async function listFiles(env, url) {
  let limit = Number(url.searchParams.get("limit") || "100");

  if (!Number.isFinite(limit)) limit = 100;
  limit = Math.max(1, Math.min(1000, Math.floor(limit)));

  const cursor = url.searchParams.get("cursor") || undefined;
  const search = (url.searchParams.get("search") || "").trim().toLowerCase();
  const type = (url.searchParams.get("type") || "").trim().toLowerCase();
  const sort = url.searchParams.get("sort") || "uploaded";
  const order = url.searchParams.get("order") || "desc";

  const result = await env.BUCKET.list({
    prefix: "files/",
    limit,
    cursor,
    include: ["customMetadata", "httpMetadata"],
  });

  let files = [];

  for (const object of result.objects) {
    const metadata = object.customMetadata || {};
    const id = object.key.slice("files/".length);

    const expiresAt =
      metadata.expiresAt === "never" ? null : Number(metadata.expiresAt || 0);

    if (expiresAt && expiresAt <= Date.now()) continue;

    const name = metadata.originalName || id;
    const mime =
      metadata.contentType ||
      object.httpMetadata?.contentType ||
      "application/octet-stream";

    if (search && !name.toLowerCase().includes(search)) continue;
    if (type && !mime.toLowerCase().includes(type)) continue;

    files.push({
      id,
      key: object.key,
      name,
      size: Number(object.size || metadata.size || 0),
      content_type: mime,
      uploaded_at: metadata.uploadedAt
        ? new Date(Number(metadata.uploadedAt)).toISOString()
        : object.uploaded.toISOString(),
      expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      etag: object.httpEtag,
      download_url: `/api/files/${encodeURIComponent(id)}`,
    });
  }

  files.sort((a, b) => {
    let av;
    let bv;

    if (sort === "name") {
      av = a.name.toLowerCase();
      bv = b.name.toLowerCase();
    } else if (sort === "size") {
      av = a.size;
      bv = b.size;
    } else {
      av = Date.parse(a.uploaded_at);
      bv = Date.parse(b.uploaded_at);
    }

    if (av < bv) return order === "asc" ? -1 : 1;
    if (av > bv) return order === "asc" ? 1 : -1;
    return 0;
  });

  return json({
    object: "list",
    data: files,
    pagination: {
      cursor: result.truncated ? result.cursor : null,
      has_more: result.truncated,
    },
    count: files.length,
  });
}

/* ============================================================
   STATS
   ============================================================ */

async function getStats(env) {
  let cursor;
  let files = 0;
  let bytes = 0;
  let expired = 0;

  do {
    const result = await env.BUCKET.list({
      prefix: "files/",
      limit: 1000,
      cursor,
      include: ["customMetadata"],
    });

    for (const object of result.objects) {
      const metadata = object.customMetadata || {};
      const expiresAt = metadata.expiresAt;

      if (
        expiresAt &&
        expiresAt !== "never" &&
        Number(expiresAt) <= Date.now()
      ) {
        expired++;
        continue;
      }

      files++;
      bytes += Number(object.size || metadata.size || 0);
    }

    cursor = result.truncated ? result.cursor : undefined;
  } while (cursor);

  return json({
    object: "stats",
    files,
    bytes,
    formatted_bytes: formatBytes(bytes),
    expired,
    bucket: BUCKET_NAME,
    version: VERSION,
  });
}

/* ============================================================
   DOWNLOAD
   ============================================================ */

async function downloadFile(request, env, id) {
  const key = `files/${id}`;

  const object = await env.BUCKET.get(key, { range: request.headers });

  if (!object) {
    return json({ error: { message: "File not found." } }, 404);
  }

  if (isExpired(object)) {
    await env.BUCKET.delete(key);
    return json({ error: { message: "File expired." } }, 410);
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "private, max-age=3600");

  const filename = sanitizeFilename(object.customMetadata?.originalName || id);
  const download = new URL(request.url).searchParams.has("download");

  headers.set("Content-Disposition", buildContentDisposition(filename, download));

  if (typeof object.size === "number") {
    headers.set("Content-Length", String(object.size));
  }

  if (object.range && typeof object.range.offset === "number") {
    const start = object.range.offset;
    const end = start + object.range.length - 1;
    headers.set("Content-Range", `bytes ${start}-${end}/${object.size}`);
  }

  const isRange = request.headers.has("Range");

  return new Response(object.body, {
    status: isRange ? 206 : 200,
    headers: {
      ...Object.fromEntries(headers.entries()),
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
    },
  });
}

/* ============================================================
   HEAD
   ============================================================ */

async function headFile(env, id) {
  const object = await env.BUCKET.head(`files/${id}`);

  if (!object) {
    return new Response(null, {
      status: 404,
      headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
    });
  }

  if (isExpired(object)) {
    await env.BUCKET.delete(`files/${id}`);
    return new Response(null, {
      status: 410,
      headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
    });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("Content-Length", String(object.size));
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");

  return new Response(null, {
    status: 200,
    headers: {
      ...Object.fromEntries(headers.entries()),
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
    },
  });
}

/* ============================================================
   DELETE
   ============================================================ */

async function deleteFile(env, id) {
  const key = `files/${id}`;
  const object = await env.BUCKET.head(key);

  if (!object) {
    return json({ error: { message: "File not found." } }, 404);
  }

  await env.BUCKET.delete(key);

  return json({ object: "file", deleted: true, id });
}

/* ============================================================
   BULK DELETE
   ============================================================ */

async function bulkDelete(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: { message: "Expected JSON body." } }, 400);
  }

  if (!Array.isArray(body.ids)) {
    return json({ error: { message: "ids must be an array." } }, 400);
  }

  if (body.ids.length === 0) {
    return json({ error: { message: "No IDs supplied." } }, 400);
  }

  if (body.ids.length > 1000) {
    return json({ error: { message: "Maximum 1000 IDs per request." } }, 400);
  }

  const keys = body.ids
    .map((id) => String(id))
    .filter((id) => id && !id.includes("/") && !id.includes("\\"))
    .map((id) => `files/${id}`);

  await env.BUCKET.delete(keys);

  return json({ object: "bulk_delete", deleted: keys.length });
}

/* ============================================================
   EXPIRATION CLEANUP
   ============================================================ */

function isExpired(object) {
  const expiresAt = object.customMetadata?.expiresAt;

  if (!expiresAt || expiresAt === "never") return false;

  const timestamp = Number(expiresAt);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

async function cleanupExpiredFiles(env) {
  let cursor;
  let deleted = 0;

  do {
    const result = await env.BUCKET.list({
      prefix: "files/",
      limit: 1000,
      cursor,
      include: ["customMetadata"],
    });

    const keys = [];

    for (const object of result.objects) {
      const expiresAt = object.customMetadata?.expiresAt;
      if (!expiresAt || expiresAt === "never") continue;

      const timestamp = Number(expiresAt);
      if (Number.isFinite(timestamp) && timestamp <= Date.now()) {
        keys.push(object.key);
      }
    }

    if (keys.length) {
      await env.BUCKET.delete(keys);
      deleted += keys.length;
    }

    cursor = result.truncated ? result.cursor : undefined;
  } while (cursor);

  console.log(`Expired cleanup deleted ${deleted} files.`);
}

/* ============================================================
   HELPERS
   ============================================================ */

function generateId() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function sanitizeFilename(filename) {
  let name = String(filename || "file");
  name = name.replace(/[/\\]/g, "_");
  name = name.replace(/[\r\n"]/g, "_");
  name = name.replace(/[\x00-\x1F\x7F]/g, "_");
  name = name.slice(0, 255);
  return name || "file";
}

function buildContentDisposition(filename, download = false) {
  const safe = sanitizeFilename(filename);
  return `${download ? "attachment" : "inline"}; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(safe)}`;
}

function formatBytes(bytes) {
  bytes = Number(bytes) || 0;
  if (!bytes) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );

  return (
    (bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2) +
    " " +
    units[index]
  );
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

/* ============================================================
   SHARED DESIGN TOKENS
   ============================================================ */

const FAVICON = `<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%230a0b0d'/%3E%3Cpath d='M9 20a5 5 0 0 1 .9-9.9A6.5 6.5 0 0 1 22.5 12 4.5 4.5 0 0 1 22 20.5H9z' fill='none' stroke='%237ddba3' stroke-width='2' stroke-linejoin='round'/%3E%3C/svg%3E">`;

const FONT_LINKS = `<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">`;

const GRAIN = `body::after {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 2000;
  pointer-events: none;
  opacity: .035;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)'/%3E%3C/svg%3E");
}`;

const BASE_CSS = `
:root {
  color-scheme: dark;
  --bg: #0a0b0d;
  --surface: #101318;
  --surface-2: #161b21;
  --border: #1f2630;
  --border-strong: #2b3541;
  --text: #e8edf2;
  --muted: #8a95a3;
  --faint: #5b6673;
  --accent: #7ddba3;
  --accent-dim: rgba(125, 219, 163, .09);
  --accent-ink: #0a120c;
  --danger: #e56a77;
  --danger-dim: rgba(229, 106, 119, .08);
  --warn: #d9b45b;
  --warn-dim: rgba(217, 180, 91, .08);
  --radius-lg: 18px;
  --radius-md: 12px;
  --radius-sm: 8px;
  --font: "Outfit", ui-sans-serif, system-ui, sans-serif;
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}

* { box-sizing: border-box; }

html { scroll-behavior: smooth; }

body {
  margin: 0;
  min-height: 100dvh;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 15px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

${GRAIN}

::selection {
  background: var(--accent);
  color: var(--accent-ink);
}

a { color: inherit; }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}

.skip {
  position: absolute;
  left: -9999px;
  top: 0;
  padding: 10px 16px;
  background: var(--accent);
  color: var(--accent-ink);
  font-weight: 600;
  z-index: 3000;
  border-radius: 0 0 var(--radius-sm) 0;
}

.skip:focus { left: 0; }

.mono {
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
}

@keyframes rise {
  from { opacity: 0; transform: translateY(14px); }
  to { opacity: 1; transform: translateY(0); }
}

.rise { animation: rise .55s cubic-bezier(.22,.8,.3,1) both; }
.rise-1 { animation-delay: .05s; }
.rise-2 { animation-delay: .14s; }
.rise-3 { animation-delay: .23s; }
.rise-4 { animation-delay: .32s; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    transition-duration: .01ms !important;
  }
  html { scroll-behavior: auto; }
}
`;

/* ============================================================
   PUBLIC WEBSITE
   ============================================================ */

function publicPage() {
  return new Response(
`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Content Delivery — private file storage on the edge</title>
<meta name="description" content="Upload once. Deliver from the edge. A private storage API backed by Cloudflare R2 with expiring links, streaming uploads, and a clean dashboard.">
${FAVICON}
${FONT_LINKS}
<style>
${BASE_CSS}

.container {
  width: min(1180px, calc(100% - 40px));
  margin: 0 auto;
}

.nav {
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  text-decoration: none;
  font-weight: 700;
  font-size: 16px;
  letter-spacing: -.01em;
}

.brand svg { display: block; }

.navLinks {
  display: flex;
  align-items: center;
  gap: 4px;
}

.navLinks a {
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  font-size: 13.5px;
  font-weight: 500;
  text-decoration: none;
  transition: color .18s, background .18s;
}

.navLinks a:hover {
  color: var(--text);
  background: rgba(255,255,255,.04);
}

.navLinks a.cta {
  color: var(--accent-ink);
  background: var(--accent);
  font-weight: 600;
  margin-left: 6px;
}

.navLinks a.cta:hover { background: #8fe6b4; }
.navLinks a.cta:active { transform: translateY(1px); }

.hero {
  position: relative;
  padding: 84px 0 110px;
}

.hero::before {
  content: "";
  position: absolute;
  top: -120px;
  left: -180px;
  width: 640px;
  height: 640px;
  background: radial-gradient(closest-side, rgba(125,219,163,.09), transparent);
  pointer-events: none;
}

.heroGrid {
  display: grid;
  grid-template-columns: 1.15fr .85fr;
  gap: 72px;
  align-items: center;
}

.eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--accent);
}

.eyebrow::before {
  content: "";
  width: 22px;
  height: 1px;
  background: var(--accent);
}

h1 {
  margin: 20px 0 18px;
  font-size: clamp(44px, 5.6vw, 68px);
  font-weight: 800;
  line-height: 1.02;
  letter-spacing: -.04em;
  text-wrap: balance;
}

h1 em {
  font-style: normal;
  color: var(--accent);
}

.heroText {
  max-width: 34rem;
  color: var(--muted);
  font-size: 16.5px;
  line-height: 1.75;
  text-wrap: pretty;
}

.heroActions {
  display: flex;
  align-items: center;
  gap: 18px;
  margin-top: 32px;
  flex-wrap: wrap;
}

.button {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border-radius: var(--radius-sm);
  font-weight: 600;
  font-size: 14px;
  text-decoration: none;
  cursor: pointer;
  border: 1px solid transparent;
  transition: transform .16s, background .16s, border-color .16s;
}

.button.primary {
  background: var(--accent);
  color: var(--accent-ink);
}

.button.primary:hover { background: #8fe6b4; transform: translateY(-1px); }
.button.primary:active { transform: translateY(1px) scale(.99); }

.button.ghost {
  color: var(--text);
  border-color: var(--border-strong);
  background: transparent;
}

.button.ghost:hover { border-color: var(--faint); transform: translateY(-1px); }
.button.ghost:active { transform: translateY(1px); }

.heroMeta {
  display: flex;
  gap: 28px;
  margin-top: 44px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
}

.heroMeta div { font-size: 12.5px; color: var(--faint); }
.heroMeta strong {
  display: block;
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 2px;
}

.auth {
  position: relative;
  padding: 30px;
  border-radius: var(--radius-lg);
  background: linear-gradient(180deg, var(--surface-2), var(--surface));
  border: 1px solid var(--border);
  box-shadow:
    0 40px 80px -30px rgba(3, 8, 5, .9),
    inset 0 1px 0 rgba(255,255,255,.04);
}

.auth::before {
  content: "";
  position: absolute;
  inset: -1px;
  border-radius: inherit;
  padding: 1px;
  background: linear-gradient(160deg, rgba(125,219,163,.45), transparent 40%);
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  pointer-events: none;
}

.authTop {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}

.authTop svg { color: var(--accent); flex: none; }

.auth h2 {
  margin: 0;
  font-size: 17px;
  font-weight: 700;
  letter-spacing: -.01em;
}

.auth .hint {
  margin: 2px 0 0;
  color: var(--muted);
  font-size: 12.5px;
}

.input {
  width: 100%;
  margin-top: 18px;
  padding: 12px 14px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: #0b0e12;
  color: var(--text);
  font: inherit;
  font-size: 14px;
  outline: none;
  transition: border-color .16s, box-shadow .16s;
}

.input::placeholder { color: var(--faint); }

.input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.loginButton {
  width: 100%;
  margin-top: 12px;
  padding: 12px;
  border: none;
  border-radius: var(--radius-sm);
  background: var(--accent);
  color: var(--accent-ink);
  font: inherit;
  font-weight: 700;
  font-size: 14px;
  cursor: pointer;
  transition: background .16s, transform .12s;
}

.loginButton:hover { background: #8fe6b4; }
.loginButton:active { transform: translateY(1px) scale(.99); }
.loginButton:disabled { opacity: .55; cursor: wait; }

#error {
  display: none;
  margin-top: 14px;
  padding: 10px 12px;
  border: 1px solid rgba(229,106,119,.35);
  border-radius: var(--radius-sm);
  background: var(--danger-dim);
  color: #f0a6ae;
  font-size: 13px;
}

.section { padding: 30px 0 90px; }

.sectionLabel {
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--accent);
}

.sectionTitle {
  margin: 12px 0 10px;
  font-size: clamp(28px, 3.4vw, 38px);
  font-weight: 700;
  letter-spacing: -.03em;
  line-height: 1.1;
  text-wrap: balance;
}

.sectionText {
  max-width: 36rem;
  color: var(--muted);
  line-height: 1.7;
  text-wrap: pretty;
}

.features {
  margin-top: 48px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.feature {
  display: grid;
  grid-template-columns: 44px 1fr 1.4fr;
  gap: 20px;
  align-items: center;
  padding: 22px 26px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface);
  transition: border-color .2s, transform .2s;
}

.feature:hover {
  border-color: var(--border-strong);
  transform: translateX(4px);
}

.feature:nth-child(even) {
  margin-left: clamp(0px, 6vw, 90px);
  background: var(--surface-2);
}

.featureIcon {
  width: 44px;
  height: 44px;
  display: grid;
  place-items: center;
  border-radius: var(--radius-sm);
  background: var(--accent-dim);
  color: var(--accent);
  flex: none;
}

.feature h3 {
  margin: 0;
  font-size: 15.5px;
  font-weight: 600;
  letter-spacing: -.01em;
}

.feature p {
  margin: 0;
  color: var(--muted);
  font-size: 13.5px;
  line-height: 1.65;
}

.endpoint {
  margin-top: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface);
  overflow: hidden;
}

.endpointHead {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
}

.method {
  padding: 3px 8px;
  border-radius: 5px;
  background: var(--accent-dim);
  color: var(--accent);
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: .04em;
}

.path {
  font-family: var(--mono);
  font-size: 12.5px;
  color: var(--text);
}

pre {
  margin: 0;
  padding: 16px 18px;
  overflow-x: auto;
  background: #07090c;
  color: #b9c6d2;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.7;
}

pre + pre { border-top: 1px solid var(--border); }

.footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  padding: 28px 0 48px;
  border-top: 1px solid var(--border);
  color: var(--faint);
  font-size: 12.5px;
}

.footer a {
  color: var(--muted);
  text-decoration: none;
  transition: color .16s;
}

.footer a:hover { color: var(--text); }

.footerLinks { display: flex; gap: 20px; }

@media (max-width: 880px) {
  .heroGrid { grid-template-columns: 1fr; gap: 48px; }
  .feature { grid-template-columns: 44px 1fr; }
  .feature p { grid-column: 2; }
  .feature:nth-child(even) { margin-left: 0; }
  .navLinks a:not(.cta) { display: none; }
}
</style>
</head>
<body>

<a class="skip" href="#main">Skip to content</a>

<div class="container">

<nav class="nav">
  <a href="/" class="brand" aria-label="Content Delivery home">
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#7ddba3" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true">
      <path d="M6.5 17a4.5 4.5 0 0 1 .8-8.9A5.5 5.5 0 0 1 18 9.6 3.8 3.8 0 0 1 17.5 17h-11z"/>
    </svg>
    Content Delivery
  </a>

  <div class="navLinks">
    <a href="#features">Features</a>
    <a href="#api">API</a>
    <a href="/docs">Docs</a>
    <a href="/dashboard" class="cta">Dashboard</a>
  </div>
</nav>

<main id="main">

<section class="hero">
  <div class="heroGrid">

    <div>
      <div class="eyebrow rise">Private R2 storage</div>

      <h1 class="rise rise-1">
        Upload once.<br>
        <em>Deliver from the edge.</em>
      </h1>

      <p class="heroText rise rise-2">
        A private file API backed by Cloudflare R2. Push any file,
        pick an expiration, and get a URL back — stream it, share it,
        or manage everything from the dashboard.
      </p>

      <div class="heroActions rise rise-3">
        <a class="button primary" href="/dashboard">
          Open dashboard
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
        </a>
        <a class="button ghost" href="/docs">API documentation</a>
      </div>

      <div class="heroMeta rise rise-4">
        <div><strong>PUT</strong>single-call upload</div>
        <div><strong>1h – ∞</strong>per-file expiration</div>
        <div><strong>206</strong>range streaming</div>
      </div>
    </div>

    <div class="auth rise rise-2">
      <div class="authTop">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
          <rect x="4" y="10" width="16" height="10" rx="2.5"/>
          <path d="M8 10V7a4 4 0 0 1 8 0v3"/>
        </svg>
        <div>
          <h2>Dashboard login</h2>
          <p class="hint">Authenticate with your API key</p>
        </div>
      </div>

      <form id="loginForm" novalidate>
        <label for="token" style="position:absolute;left:-9999px">API key</label>
        <input
          id="token"
          class="input mono"
          type="password"
          placeholder="Paste your API key"
          autocomplete="current-password"
          required
        >
        <button class="loginButton" type="submit">Sign in</button>
      </form>

      <div id="error" role="alert"></div>
    </div>

  </div>
</section>

<section id="features" class="section">
  <div class="sectionLabel">Features</div>
  <h2 class="sectionTitle">Storage built around the API, not the other way round</h2>
  <p class="sectionText">
    Everything is private by default. The Worker holds the only key,
    R2 holds the bytes, and every operation is one HTTP call.
  </p>

  <div class="features">

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 17c3-1 5-6 8-6s5 5 8 4"/><path d="M4 7c3 1 5 6 8 6s5-5 8-4"/></svg>
      </div>
      <h3>Streaming end to end</h3>
      <p>Request bodies pipe straight into R2 with no buffering and no size cap. Downloads support HTTP range requests for seeking and resuming.</p>
    </div>

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>
      </div>
      <h3>Per-file expiration</h3>
      <p>One hour to ninety days, or never. A scheduled sweep removes expired objects automatically.</p>
    </div>

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>
      </div>
      <h3>Search and sorting</h3>
      <p>Filter by filename or MIME type, sort by name, size, or upload time — all server-side.</p>
    </div>

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="8" height="8" rx="1.5"/><rect x="13" y="4" width="8" height="8" rx="1.5"/><rect x="3" y="14" width="8" height="6" rx="1.5"/><rect x="13" y="14" width="8" height="6" rx="1.5"/></svg>
      </div>
      <h3>Bulk management</h3>
      <p>Select any set of files and remove them in a single API call, up to a thousand at a time.</p>
    </div>

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m8 9-4 3 4 3M16 9l4 3-4 3M13 5l-2 14"/></svg>
      </div>
      <h3>API-first</h3>
      <p>The dashboard is a convenience, not a requirement. Every action maps to a documented REST endpoint.</p>
    </div>

    <div class="feature">
      <div class="featureIcon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
      </div>
      <h3>Private by default</h3>
      <p>Nothing is public. Every read and write passes through Bearer authentication on the Worker.</p>
    </div>

  </div>
</section>

<section id="api" class="section">
  <div class="sectionLabel">Quick start</div>
  <h2 class="sectionTitle">Simple requests, predictable responses</h2>

  <div class="endpoint">
    <div class="endpointHead">
      <span class="method">PUT</span>
      <span class="path">/api/upload</span>
    </div>
    <pre><code>curl -X PUT \
  "https://cdn.pushkarsingh4343.workers.dev/api/upload?filename=photo.jpg&expires=7d" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: image/jpeg" \
  --data-binary "@photo.jpg"</code></pre>
  <pre><code>{
  "object": "file",
  "status": "complete",
  "id": "a4e3c1…",
  "name": "photo.jpg",
  "download_url": "https://cdn.pushkarsingh4343.workers.dev/api/files/a4e3c1…"
}</code></pre>
  </div>

  <div class="endpoint">
    <div class="endpointHead">
      <span class="method">GET</span>
      <span class="path">/api/files</span>
    </div>
    <pre><code>curl \
  "https://cdn.pushkarsingh4343.workers.dev/api/files?search=photo&sort=size&order=desc" \
  -H "Authorization: Bearer YOUR_API_KEY"</code></pre>
  </div>

  <div class="endpoint">
    <div class="endpointHead">
      <span class="method">GET</span>
      <span class="path">/api/files/:id</span>
    </div>
    <pre><code>curl \
  "https://cdn.pushkarsingh4343.workers.dev/api/files/FILE_ID" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -o file</code></pre>
  </div>
</section>

</main>

<footer class="footer">
  <span>Content Delivery — Cloudflare Workers + R2</span>
  <div class="footerLinks">
    <a href="/docs">Documentation</a>
    <a href="/dashboard">Dashboard</a>
  </div>
</footer>

</div>

<script>
document
  .getElementById("loginForm")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const token = document.getElementById("token").value;
    const error = document.getElementById("error");
    const button = event.target.querySelector("button");

    error.style.display = "none";

    if (!token.trim()) {
      error.textContent = "Enter your API key to continue.";
      error.style.display = "block";
      return;
    }

    button.disabled = true;
    button.textContent = "Signing in…";

    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ token }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error?.message || "Login failed.");
      }

      location.href = "/dashboard";
    } catch (err) {
      error.textContent = err.message;
      error.style.display = "block";
      button.disabled = false;
      button.textContent = "Sign in";
    }
  });
</script>

</body>
</html>`,
    {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

/* ============================================================
   DOCUMENTATION
   ============================================================ */

function docsPage() {
  return new Response(
`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API documentation — Content Delivery</title>
<meta name="description" content="REST API reference for Content Delivery: uploads, expiration, listing, downloads, stats, and deletion.">
${FAVICON}
${FONT_LINKS}
<style>
${BASE_CSS}

.container {
  width: min(880px, calc(100% - 40px));
  margin: 0 auto;
  padding: 24px 0 80px;
}

.nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 56px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 15.5px;
  letter-spacing: -.01em;
  text-decoration: none;
}

.back {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 13px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  color: var(--muted);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
  transition: color .16s, border-color .16s;
}

.back:hover { color: var(--text); border-color: var(--faint); }

.hero { margin-bottom: 40px; }

.hero h1 {
  margin: 0 0 12px;
  font-size: clamp(34px, 5vw, 46px);
  font-weight: 800;
  letter-spacing: -.035em;
  line-height: 1.05;
}

.hero p {
  color: var(--muted);
  line-height: 1.75;
  max-width: 40rem;
  text-wrap: pretty;
}

.notice {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 16px 18px;
  border: 1px solid rgba(125,219,163,.3);
  border-radius: var(--radius-md);
  background: var(--accent-dim);
  color: #a9e8c4;
  font-size: 13.5px;
  line-height: 1.7;
  margin-bottom: 32px;
}

.notice svg { flex: none; margin-top: 2px; color: var(--accent); }

.notice code {
  font-family: var(--mono);
  font-size: 12px;
  background: rgba(0,0,0,.3);
  padding: 2px 6px;
  border-radius: 5px;
}

h2.group {
  margin: 44px 0 14px;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--faint);
  font-family: var(--mono);
}

.card {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  background: var(--surface);
  margin-bottom: 14px;
}

.head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
}

.method {
  padding: 3px 8px;
  border-radius: 5px;
  background: var(--accent-dim);
  color: var(--accent);
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: .04em;
}

.method.post { background: rgba(120,170,255,.1); color: #8fbdf5; }
.method.delete { background: var(--danger-dim); color: var(--danger); }

.path { font-family: var(--mono); font-size: 12.5px; }

.body { padding: 4px 0 0; }

.body .note {
  padding: 14px 18px 0;
  color: var(--muted);
  font-size: 13.5px;
  line-height: 1.65;
}

.body .note code {
  font-family: var(--mono);
  font-size: 12px;
  background: rgba(255,255,255,.05);
  padding: 1px 5px;
  border-radius: 4px;
}

pre {
  margin: 14px 0 0;
  padding: 16px 18px;
  overflow-x: auto;
  background: #07090c;
  color: #b9c6d2;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.7;
}

pre + pre { border-top: 1px solid var(--border); }

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  text-align: left;
  padding: 10px 18px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}

tr:last-child td { border-bottom: none; }

th {
  color: var(--faint);
  font-weight: 500;
  font-size: 11px;
  letter-spacing: .08em;
  text-transform: uppercase;
}

td code {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--accent);
}

.footer {
  margin-top: 56px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
  color: var(--faint);
  font-size: 12.5px;
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}

.footer a { color: var(--muted); text-decoration: none; }
.footer a:hover { color: var(--text); }
</style>
</head>
<body>

<a class="skip" href="#main">Skip to content</a>

<div class="container">

<nav class="nav">
  <a href="/" class="brand">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#7ddba3" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true">
      <path d="M6.5 17a4.5 4.5 0 0 1 .8-8.9A5.5 5.5 0 0 1 18 9.6 3.8 3.8 0 0 1 17.5 17h-11z"/>
    </svg>
    Content Delivery
  </a>
  <a class="back" href="/">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M19 12H5M11 18l-6-6 6-6"/></svg>
    Back to site
  </a>
</nav>

<main id="main">

<header class="hero rise">
  <h1>API documentation</h1>
  <p>
    An authenticated REST API over your Cloudflare R2 bucket. Files support
    streaming upload and download, per-file expiration, search, sorting,
    and bulk deletion.
  </p>
</header>

<div class="notice rise rise-1">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
    <rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>
  </svg>
  <div>
    Every request needs <code>Authorization: Bearer YOUR_API_KEY</code>.
    The Worker reads the key from its <code>API_KEY</code> environment variable,
    and all responses are JSON unless the endpoint streams a file.
  </div>
</div>

<h2 class="group">Status</h2>

<div class="card">
  <div class="head"><span class="method">GET</span><span class="path">/api/health</span></div>
  <div class="body">
    <pre><code>curl "https://cdn.pushkarsingh4343.workers.dev/api/health" \
  -H "Authorization: Bearer YOUR_API_KEY"</code></pre>
    <pre><code>{
  "object": "health",
  "status": "ok",
  "service": "Content Delivery",
  "version": "${VERSION}",
  "bucket": "${BUCKET_NAME}",
  "timestamp": "2026-08-15T09:41:22.810Z"
}</code></pre>
  </div>
</div>

<div class="card">
  <div class="head"><span class="method">GET</span><span class="path">/api/stats</span></div>
  <div class="body">
    <pre><code>curl "https://cdn.pushkarsingh4343.workers.dev/api/stats" \
  -H "Authorization: Bearer YOUR_API_KEY"</code></pre>
    <pre><code>{
  "object": "stats",
  "files": 12,
  "bytes": 48192031,
  "formatted_bytes": "45.96 MB",
  "expired": 0,
  "bucket": "${BUCKET_NAME}",
  "version": "${VERSION}"
}</code></pre>
  </div>
</div>

<h2 class="group">Uploads</h2>

<div class="card">
  <div class="head"><span class="method">PUT</span><span class="path">/api/upload</span></div>
  <div class="body">
    <p class="note">Standard streaming upload. The body pipes directly into R2 with no size cap.</p>
    <pre><code>curl -X PUT \
  "https://cdn.pushkarsingh4343.workers.dev/api/upload?filename=video.mp4&expires=7d" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: video/mp4" \
  --data-binary "@video.mp4"</code></pre>
    <pre><code>{
  "object": "file",
  "status": "complete",
  "id": "abc123…",
  "key": "files/abc123…",
  "name": "video.mp4",
  "size": 10485760,
  "content_type": "video/mp4",
  "uploaded_at": "…",
  "expires_at": "…",
  "download_url": "https://cdn.pushkarsingh4343.workers.dev/api/files/abc123…"
}</code></pre>
  </div>
</div>

<div class="card">
  <div class="head"><span class="method post">POST</span><span class="path">/api/upload</span></div>
  <div class="body">
    <p class="note">Multipart form upload, for browser forms and <code>curl -F</code>.</p>
    <pre><code>curl -X POST \
  "https://cdn.pushkarsingh4343.workers.dev/api/upload?expires=30d" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@document.pdf"</code></pre>
  </div>
</div>

<h2 class="group">Files</h2>

<div class="card">
  <div class="head"><span class="method">GET</span><span class="path">/api/files</span></div>
  <div class="body">
    <p class="note">
      Query parameters: <code>limit</code>, <code>cursor</code>, <code>search</code>,
      <code>type</code>, <code>sort</code> (uploaded | name | size), <code>order</code> (asc | desc).
    </p>
    <pre><code>curl \
  "https://cdn.pushkarsingh4343.workers.dev/api/files?search=photo&sort=size&order=desc" \
  -H "Authorization: Bearer YOUR_API_KEY"</code></pre>
    <pre><code>{
  "object": "list",
  "data": [
    {
      "id": "abc123…",
      "name": "photo.jpg",
      "size": 245821,
      "content_type": "image/jpeg",
      "uploaded_at": "…",
      "expires_at": "…",
      "etag": "…",
      "download_url": "/api/files/abc123…"
    }
  ],
  "pagination": { "cursor": null, "has_more": false },
  "count": 1
}</code></pre>
  </div>
</div>

<div class="card">
  <div class="head"><span class="method">GET</span><span class="path">/api/files/:id</span></div>
  <div class="body">
    <pre><code>curl \
  "https://cdn.pushkarsingh4343.workers.dev/api/files/abc123…" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -o file</code></pre>
    <p class="note" style="padding-bottom:16px">
      Streams inline by default. Add <code>?download=1</code> to force an attachment.
      <code>Range</code> requests return <code>206</code> with a <code>Content-Range</code> header.
    </p>
  </div>
</div>

<div class="card">
  <div class="head"><span class="method delete">DELETE</span><span class="path">/api/files/:id</span></div>
  <div class="body">
    <pre><code>curl -X DELETE \
  "https://cdn.pushkarsingh4343.workers.dev/api/files/abc123…" \
  -H "Authorization: Bearer YOUR_API_KEY"</code></pre>
    <pre><code>{ "object": "file", "deleted": true, "id": "abc123…" }</code></pre>
  </div>
</div>

<div class="card">
  <div class="head"><span class="method delete">DELETE</span><span class="path">/api/files</span></div>
  <div class="body">
    <p class="note">Bulk delete, up to 1000 IDs per call.</p>
    <pre><code>curl -X DELETE \
  "https://cdn.pushkarsingh4343.workers.dev/api/files" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ids":["abc123","def456"]}'</code></pre>
  </div>
</div>

<h2 class="group">Expiration values</h2>

<div class="card">
  <div class="body">
    <table>
      <tr><th>Value</th><th>Lifetime</th></tr>
      <tr><td><code>1h</code></td><td>1 hour</td></tr>
      <tr><td><code>6h</code></td><td>6 hours</td></tr>
      <tr><td><code>12h</code></td><td>12 hours</td></tr>
      <tr><td><code>1d</code></td><td>1 day</td></tr>
      <tr><td><code>3d</code></td><td>3 days</td></tr>
      <tr><td><code>7d</code></td><td>7 days (default)</td></tr>
      <tr><td><code>30d</code></td><td>30 days</td></tr>
      <tr><td><code>90d</code></td><td>90 days</td></tr>
      <tr><td><code>never</code></td><td>No expiration</td></tr>
    </table>
  </div>
</div>

</main>

<footer class="footer">
  <span>Content Delivery — Cloudflare Workers + R2</span>
  <a href="/dashboard">Dashboard →</a>
</footer>

</div>
</body>
</html>`,
    {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

/* ============================================================
   DASHBOARD
   ============================================================ */

function dashboardPage() {
  return new Response(
`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — Content Delivery</title>
<meta name="description" content="Manage files in your Content Delivery bucket.">
${FAVICON}
${FONT_LINKS}
<style>
${BASE_CSS}

.container {
  max-width: 1240px;
  margin: 0 auto;
  padding: 20px 20px 70px;
}

.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 26px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
}

.brand svg { display: block; }

.title { font-size: 16px; font-weight: 700; letter-spacing: -.01em; }

.subtitle {
  color: var(--faint);
  font-family: var(--mono);
  font-size: 11px;
  margin-top: 1px;
}

.actions { display: flex; gap: 8px; flex-wrap: wrap; }

button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 13px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  color: var(--text);
  font: inherit;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  transition: transform .14s, background .14s, border-color .14s;
}

button:hover { border-color: var(--faint); transform: translateY(-1px); }
button:active { transform: translateY(1px) scale(.99); }

button.primary {
  background: var(--accent);
  border-color: transparent;
  color: var(--accent-ink);
}

button.primary:hover { background: #8fe6b4; }

button.danger {
  color: #f0a6ae;
  background: var(--danger-dim);
  border-color: rgba(229,106,119,.3);
}

button.danger:hover { border-color: rgba(229,106,119,.55); }

button:disabled { opacity: .45; cursor: not-allowed; transform: none; }

.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 14px;
}

.stat {
  position: relative;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 16px 18px;
  background: var(--surface);
  overflow: hidden;
}

.stat::before {
  content: "";
  position: absolute;
  top: 0;
  left: 18px;
  right: 18px;
  height: 1px;
  background: linear-gradient(90deg, var(--accent), transparent);
  opacity: .5;
}

.statLabel {
  color: var(--faint);
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: .12em;
  text-transform: uppercase;
}

.statValue {
  margin-top: 6px;
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  font-size: 23px;
  font-weight: 600;
  letter-spacing: -.02em;
}

.upload {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px;
  background: var(--surface);
  margin-bottom: 14px;
}

.drop {
  padding: 34px 20px;
  border: 1.5px dashed var(--border-strong);
  border-radius: var(--radius-md);
  text-align: center;
  transition: border-color .18s, background .18s;
}

.drop.drag {
  border-color: var(--accent);
  background: var(--accent-dim);
}

.uploadIcon {
  width: 46px;
  height: 46px;
  display: grid;
  place-items: center;
  margin: 0 auto 12px;
  border-radius: var(--radius-md);
  background: var(--accent-dim);
  color: var(--accent);
}

.uploadTitle { font-weight: 700; font-size: 15.5px; letter-spacing: -.01em; }

.muted { color: var(--muted); }
.small { font-size: 12px; }

.fileInput {
  width: 100%;
  margin-top: 16px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: #0b0e12;
  color: var(--text);
  font: inherit;
  font-size: 13px;
}

.fileInput::file-selector-button {
  margin-right: 12px;
  padding: 6px 12px;
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  background: var(--surface-2);
  color: var(--text);
  font: inherit;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}

.uploadControls {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  max-width: 560px;
  margin: 14px auto 0;
}

select, .search {
  width: 100%;
  padding: 9px 11px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: #0b0e12;
  color: var(--text);
  outline: none;
  font: inherit;
  font-size: 13px;
  transition: border-color .16s, box-shadow .16s;
}

select:focus, .search:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.progress {
  margin-top: 10px;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 11.5px;
  text-align: center;
  min-height: 16px;
}

.files {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
  background: var(--surface);
}

.fileTop {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 15px 18px;
  border-bottom: 1px solid var(--border);
}

.fileTop strong { font-size: 14.5px; letter-spacing: -.01em; }

.fileSearch {
  display: grid;
  grid-template-columns: 1fr 170px 140px;
  gap: 8px;
  padding: 12px 18px;
  border-bottom: 1px solid var(--border);
}

.bulk {
  display: none;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 18px;
  border-bottom: 1px solid rgba(125,219,163,.25);
  background: var(--accent-dim);
}

.tableWrap { overflow-x: auto; }

table {
  width: 100%;
  min-width: 920px;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 10px 12px;
  color: var(--faint);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: .1em;
  border-bottom: 1px solid var(--border);
}

td {
  padding: 11px 12px;
  border-bottom: 1px solid #141a21;
  font-size: 12.5px;
}

tbody tr { transition: background .12s; }
tbody tr:hover td { background: rgba(255,255,255,.015); }

td.num {
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  color: var(--muted);
}

.fileCell {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 260px;
}

.fileIcon {
  width: 34px;
  height: 34px;
  border-radius: var(--radius-sm);
  display: grid;
  place-items: center;
  background: var(--surface-2);
  color: var(--accent);
  flex: none;
}

.fileName {
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
  font-size: 13px;
}

.fileType {
  margin-top: 2px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--faint);
}

.pill {
  display: inline-flex;
  padding: 3px 8px;
  border-radius: 5px;
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 500;
}

.pill.green { color: var(--accent); background: var(--accent-dim); }
.pill.yellow { color: var(--warn); background: var(--warn-dim); }

.rowButtons { display: flex; gap: 5px; }

.rowButtons button {
  padding: 5px 9px;
  font-size: 11px;
  font-weight: 600;
}

.skel {
  height: 14px;
  border-radius: 5px;
  background: linear-gradient(90deg, var(--surface-2) 25%, #1c232c 50%, var(--surface-2) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.3s infinite;
}

@keyframes shimmer {
  from { background-position: 200% 0; }
  to { background-position: -200% 0; }
}

.empty {
  padding: 60px 20px;
  text-align: center;
}

.emptyIcon {
  width: 52px;
  height: 52px;
  margin: 0 auto 14px;
  display: grid;
  place-items: center;
  border-radius: var(--radius-md);
  background: var(--surface-2);
  color: var(--faint);
}

.emptyTitle { font-weight: 700; font-size: 15px; }
.emptyText { color: var(--muted); font-size: 13px; margin-top: 4px; }

.modal {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 900;
  align-items: center;
  justify-content: center;
  padding: 18px;
  background: rgba(4,6,8,.7);
  backdrop-filter: blur(4px);
}

.modalCard {
  width: min(680px, 100%);
  max-height: 88vh;
  overflow: auto;
  padding: 20px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-lg);
  background: var(--surface);
  box-shadow: 0 40px 90px -20px rgba(0,0,0,.7);
  animation: rise .3s cubic-bezier(.22,.8,.3,1) both;
}

.modalTop {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
}

.metaGrid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.meta {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: #0b0e12;
}

.metaLabel {
  color: var(--faint);
  font-family: var(--mono);
  font-size: 9.5px;
  text-transform: uppercase;
  letter-spacing: .1em;
}

.metaValue {
  margin-top: 5px;
  font-size: 12.5px;
  word-break: break-all;
}

.metaValue.mono { font-size: 11.5px; }

#toast {
  display: none;
  position: fixed;
  right: 18px;
  bottom: 18px;
  z-index: 1200;
  max-width: 360px;
  padding: 12px 16px;
  border: 1px solid var(--border-strong);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  box-shadow: 0 20px 50px rgba(0,0,0,.5);
  font-size: 13px;
  animation: rise .25s cubic-bezier(.22,.8,.3,1) both;
}

#toast.err { border-left-color: var(--danger); }

@media (max-width: 900px) {
  .stats { grid-template-columns: repeat(2, 1fr); }
  .fileSearch { grid-template-columns: 1fr; }
}

@media (max-width: 600px) {
  .uploadControls { grid-template-columns: 1fr; }
  .subtitle { display: none; }
  .metaGrid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<a class="skip" href="#main">Skip to content</a>

<div class="container">

<header class="topbar">
  <div class="brand">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#7ddba3" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true">
      <path d="M6.5 17a4.5 4.5 0 0 1 .8-8.9A5.5 5.5 0 0 1 18 9.6 3.8 3.8 0 0 1 17.5 17h-11z"/>
    </svg>
    <div>
      <div class="title">Content Delivery</div>
      <div class="subtitle">bucket: ${BUCKET_NAME}</div>
    </div>
  </div>

  <div class="actions">
    <button onclick="location.href='/docs'">API docs</button>
    <button onclick="refreshAll()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5"/></svg>
      Refresh
    </button>
    <button class="danger" onclick="logout()">Log out</button>
  </div>
</header>

<main id="main">

<section class="stats" aria-label="Storage statistics">
  <div class="stat">
    <div class="statLabel">Files</div>
    <div id="statFiles" class="statValue">—</div>
  </div>
  <div class="stat">
    <div class="statLabel">Storage used</div>
    <div id="statStorage" class="statValue">—</div>
  </div>
  <div class="stat">
    <div class="statLabel">Expired</div>
    <div id="statExpired" class="statValue">—</div>
  </div>
  <div class="stat">
    <div class="statLabel">Version</div>
    <div class="statValue" style="font-size:16px">v${VERSION}</div>
  </div>
</section>

<section class="upload" aria-label="Upload">
  <div id="drop" class="drop">
    <div class="uploadIcon">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 16V4M6 10l6-6 6 6"/><path d="M4 20h16"/></svg>
    </div>

    <div class="uploadTitle">Drop a file, or browse</div>
    <div class="muted small" style="margin-top:3px">
      Images, video, archives, documents — streamed straight to R2.
    </div>

    <input id="fileInput" class="fileInput" type="file" aria-label="Choose a file">

    <div class="uploadControls">
      <select id="expiry" aria-label="Expiration">
        <option value="1h">Expires in 1 hour</option>
        <option value="6h">Expires in 6 hours</option>
        <option value="12h">Expires in 12 hours</option>
        <option value="1d">Expires in 1 day</option>
        <option value="3d">Expires in 3 days</option>
        <option value="7d" selected>Expires in 7 days</option>
        <option value="30d">Expires in 30 days</option>
        <option value="90d">Expires in 90 days</option>
        <option value="never">Never expires</option>
      </select>

      <button id="uploadButton" class="primary" onclick="upload()">Upload</button>
    </div>

    <div id="progress" class="progress" role="status"></div>
  </div>
</section>

<section class="files" aria-label="Files">
  <div class="fileTop">
    <div>
      <strong>Files</strong>
      <span id="resultCount" class="muted small" style="margin-left:8px">—</span>
    </div>
  </div>

  <div id="bulk" class="bulk">
    <span id="selectedText" class="small">0 selected</span>
    <div style="display:flex;gap:6px">
      <button onclick="clearSelection()">Clear</button>
      <button class="danger" onclick="bulkDelete()">Delete selected</button>
    </div>
  </div>

  <div class="fileSearch">
    <input id="search" class="search" placeholder="Search by filename…" oninput="debouncedLoad()" aria-label="Search files">
    <select id="typeFilter" onchange="loadFiles()" aria-label="Filter by type">
      <option value="">All types</option>
      <option value="image/">Images</option>
      <option value="video/">Videos</option>
      <option value="audio/">Audio</option>
      <option value="application/pdf">PDF</option>
      <option value="text/">Text</option>
      <option value="application/zip">ZIP</option>
    </select>
    <select id="sort" onchange="loadFiles()" aria-label="Sort by">
      <option value="uploaded">Newest first</option>
      <option value="name">Name</option>
      <option value="size">Size</option>
    </select>
  </div>

  <div class="tableWrap">
    <table>
      <thead>
        <tr>
          <th style="width:34px"><input id="selectAll" type="checkbox" onchange="toggleAll()" aria-label="Select all"></th>
          <th>File</th>
          <th>Size</th>
          <th>Uploaded</th>
          <th>Expires</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="files"></tbody>
    </table>
  </div>
</section>

</main>
</div>

<div id="toast" role="status"></div>

<div id="modal" class="modal" role="dialog" aria-modal="true" aria-label="File information">
  <div class="modalCard">
    <div class="modalTop">
      <strong>File information</strong>
      <button onclick="closeModal()" aria-label="Close">✕</button>
    </div>
    <div id="modalBody" class="metaGrid"></div>
  </div>
</div>

<script>
let files = [];
const selected = new Set();
let timer = null;

/* ---------- API ---------- */

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, credentials: "same-origin" });

  if (response.status === 401) {
    location.href = "/";
    throw new Error("Session expired.");
  }

  return response;
}

async function refreshAll() {
  await Promise.all([loadFiles(), loadStats()]);
}

/* ---------- file list ---------- */

function skeletonRows() {
  let rows = "";
  for (let i = 0; i < 5; i++) {
    rows += \`
      <tr>
        <td></td>
        <td><div class="skel" style="width:70%"></div></td>
        <td><div class="skel" style="width:46px"></div></td>
        <td><div class="skel" style="width:90px"></div></td>
        <td><div class="skel" style="width:56px"></div></td>
        <td><div class="skel" style="width:150px"></div></td>
      </tr>\`;
  }
  return rows;
}

async function loadFiles() {
  const tbody = document.getElementById("files");
  tbody.innerHTML = skeletonRows();

  const params = new URLSearchParams({
    limit: "1000",
    sort: document.getElementById("sort").value,
    order: "desc",
  });

  const search = document.getElementById("search").value.trim();
  const type = document.getElementById("typeFilter").value;

  if (search) params.set("search", search);
  if (type) params.set("type", type);

  try {
    const response = await api("/api/files?" + params);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Failed to load files.");
    }

    files = data.data || [];
    renderFiles(files);
  } catch (error) {
    tbody.innerHTML = \`
      <tr><td colspan="6">
        <div class="empty">
          <div class="emptyTitle">Could not load files</div>
          <div class="emptyText">\${escapeHtml(error.message)}</div>
        </div>
      </td></tr>\`;
  }
}

function renderFiles(list) {
  const tbody = document.getElementById("files");

  document.getElementById("resultCount").textContent =
    list.length + (list.length === 1 ? " result" : " results");

  if (!list.length) {
    tbody.innerHTML = \`
      <tr><td colspan="6">
        <div class="empty">
          <div class="emptyIcon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6.5 17a4.5 4.5 0 0 1 .8-8.9A5.5 5.5 0 0 1 18 9.6 3.8 3.8 0 0 1 17.5 17h-11z"/></svg>
          </div>
          <div class="emptyTitle">Nothing here yet</div>
          <div class="emptyText">Upload your first file above and it will show up in this list.</div>
        </div>
      </td></tr>\`;
    updateBulk();
    return;
  }

  tbody.innerHTML = "";

  for (const file of list) {
    const tr = document.createElement("tr");

    const expiry = file.expires_at
      ? \`<span class="pill yellow">\${relative(file.expires_at)}</span>\`
      : \`<span class="pill green">never</span>\`;

    tr.innerHTML = \`
      <td><input type="checkbox" \${selected.has(file.id) ? "checked" : ""}
        onchange="selectFile('\${attr(file.id)}', this.checked)" aria-label="Select file"></td>
      <td>
        <div class="fileCell">
          <div class="fileIcon">\${fileIcon(file.content_type)}</div>
          <div>
            <div class="fileName" title="\${escapeHtml(file.name)}">\${escapeHtml(file.name)}</div>
            <div class="fileType">\${escapeHtml(file.content_type)}</div>
          </div>
        </div>
      </td>
      <td class="num">\${formatBytes(file.size)}</td>
      <td class="num">\${formatDate(file.uploaded_at)}</td>
      <td>\${expiry}</td>
      <td>
        <div class="rowButtons">
          <button onclick="openFile('\${attr(file.id)}')">Open</button>
          <button onclick="downloadFile('\${attr(file.id)}')">Download</button>
          <button onclick="showInfo('\${attr(file.id)}')">Info</button>
          <button class="danger" onclick="deleteFile('\${attr(file.id)}')">Delete</button>
        </div>
      </td>\`;

    tbody.appendChild(tr);
  }

  updateBulk();
}

/* ---------- stats ---------- */

async function loadStats() {
  try {
    const response = await api("/api/stats");
    const data = await response.json();
    if (!response.ok) return;

    document.getElementById("statFiles").textContent = data.files;
    document.getElementById("statStorage").textContent = data.formatted_bytes;
    document.getElementById("statExpired").textContent = data.expired;
  } catch {}
}

/* ---------- upload ---------- */

async function upload() {
  const input = document.getElementById("fileInput");
  const file = input.files[0];

  if (!file) {
    toast("Choose a file first.", true);
    return;
  }

  const expiry = document.getElementById("expiry").value;
  const progress = document.getElementById("progress");
  const button = document.getElementById("uploadButton");

  button.disabled = true;
  progress.textContent = "uploading " + file.name + "…";

  try {
    const url = "/api/upload?" + new URLSearchParams({
      filename: file.name,
      expires: expiry,
    });

    const response = await api(url, {
      method: "PUT",
      headers: { "Content-Type": file.type || "application/octet-stream" },
      body: file,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Upload failed.");
    }

    progress.textContent = "upload complete";
    toast("File uploaded.");

    input.value = "";
    await refreshAll();
  } catch (error) {
    progress.textContent = "";
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

/* ---------- file actions ---------- */

function openFile(id) {
  window.open("/api/files/" + encodeURIComponent(id), "_blank");
}

function downloadFile(id) {
  window.open("/api/files/" + encodeURIComponent(id) + "?download=1", "_blank");
}

async function deleteFile(id) {
  const file = files.find((f) => f.id === id);

  if (!confirm("Delete " + (file?.name || "this file") + " permanently?")) {
    return;
  }

  try {
    const response = await api("/api/files/" + encodeURIComponent(id), {
      method: "DELETE",
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Delete failed.");
    }

    selected.delete(id);
    toast("File deleted.");
    await refreshAll();
  } catch (error) {
    toast(error.message, true);
  }
}

/* ---------- bulk ---------- */

function selectFile(id, checked) {
  if (checked) selected.add(id);
  else selected.delete(id);
  updateBulk();
}

function toggleAll() {
  const checked = document.getElementById("selectAll").checked;

  if (checked) {
    for (const file of files) selected.add(file.id);
  } else {
    selected.clear();
  }

  renderFiles(files);
}

function clearSelection() {
  selected.clear();
  document.getElementById("selectAll").checked = false;
  renderFiles(files);
}

function updateBulk() {
  const bar = document.getElementById("bulk");
  const text = document.getElementById("selectedText");

  text.textContent = selected.size + " selected";
  bar.style.display = selected.size ? "flex" : "none";
}

async function bulkDelete() {
  if (!selected.size) return;

  if (!confirm("Delete " + selected.size + " selected files?")) return;

  try {
    const response = await api("/api/files", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: Array.from(selected) }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Bulk delete failed.");
    }

    selected.clear();
    toast(data.deleted + " files deleted.");
    await refreshAll();
  } catch (error) {
    toast(error.message, true);
  }
}

/* ---------- info modal ---------- */

function showInfo(id) {
  const file = files.find((f) => f.id === id);
  if (!file) return;

  const modal = document.getElementById("modal");
  const body = document.getElementById("modalBody");
  const url = location.origin + "/api/files/" + file.id;

  body.innerHTML = \`
    <div class="meta"><div class="metaLabel">Name</div><div class="metaValue">\${escapeHtml(file.name)}</div></div>
    <div class="meta"><div class="metaLabel">Size</div><div class="metaValue mono">\${formatBytes(file.size)}</div></div>
    <div class="meta"><div class="metaLabel">Content type</div><div class="metaValue mono">\${escapeHtml(file.content_type)}</div></div>
    <div class="meta"><div class="metaLabel">Uploaded</div><div class="metaValue">\${formatDate(file.uploaded_at)}</div></div>
    <div class="meta"><div class="metaLabel">Expires</div><div class="metaValue">\${file.expires_at ? formatDate(file.expires_at) : "Never"}</div></div>
    <div class="meta"><div class="metaLabel">ID</div><div class="metaValue mono">\${escapeHtml(file.id)}</div></div>
    <div class="meta"><div class="metaLabel">ETag</div><div class="metaValue mono">\${escapeHtml(file.etag || "—")}</div></div>
    <div class="meta" style="grid-column:1/-1"><div class="metaLabel">API URL</div><div class="metaValue mono">\${escapeHtml(url)}</div></div>\`;

  modal.style.display = "flex";
}

function closeModal() {
  document.getElementById("modal").style.display = "none";
}

document.getElementById("modal").addEventListener("click", (event) => {
  if (event.target.id === "modal") closeModal();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
});

/* ---------- drag & drop ---------- */

const drop = document.getElementById("drop");
const fileInput = document.getElementById("fileInput");

drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("drag");
});

drop.addEventListener("dragleave", (event) => {
  if (!drop.contains(event.relatedTarget)) {
    drop.classList.remove("drag");
  }
});

drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("drag");

  if (event.dataTransfer.files.length) {
    fileInput.files = event.dataTransfer.files;
  }
});

/* ---------- search ---------- */

function debouncedLoad() {
  clearTimeout(timer);
  timer = setTimeout(loadFiles, 250);
}

/* ---------- helpers ---------- */

function fileIcon(type) {
  const svg = (inner) =>
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + inner + "</svg>";

  if (type.startsWith("image/"))
    return svg('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.6"/><path d="m5 19 5.5-5.5 3 3L17 13l4 4"/>');
  if (type.startsWith("video/"))
    return svg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m10 9 5 3-5 3z"/>');
  if (type.startsWith("audio/"))
    return svg('<path d="M9 18V6l10-2v11"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="16.5" cy="15" r="2.5"/>');
  if (type.includes("pdf"))
    return svg('<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>');
  if (type.includes("zip") || type.includes("compressed"))
    return svg('<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M12 3v4M10 7h4M12 11v2"/>');
  if (type.includes("json") || type.startsWith("text/"))
    return svg('<path d="m8 9-3 3 3 3M16 9l3 3-3 3"/>');
  return svg('<path d="M4 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>');
}

function formatBytes(bytes) {
  bytes = Number(bytes) || 0;
  if (!bytes) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );

  return (
    (bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2) +
    " " +
    units[index]
  );
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function relative(value) {
  const diff = new Date(value).getTime() - Date.now();
  if (diff <= 0) return "expired";

  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return "in " + minutes + "m";

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return "in " + hours + "h";

  return "in " + Math.floor(hours / 24) + "d";
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

function attr(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function toast(message, isError = false) {
  const element = document.getElementById("toast");

  element.textContent = message;
  element.className = isError ? "err" : "";
  element.style.display = "block";

  clearTimeout(window.__toast);
  window.__toast = setTimeout(() => {
    element.style.display = "none";
  }, 3500);
}

async function logout() {
  try {
    await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  } finally {
    location.href = "/";
  }
}

/* initial load */
refreshAll();
</script>

</body>
</html>`,
    {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

/* ============================================================
   404 PAGE
   ============================================================ */

function notFoundPage() {
  return new Response(
`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Page not found — Content Delivery</title>
${FAVICON}
${FONT_LINKS}
<style>
${BASE_CSS}

.wrap {
  min-height: 100dvh;
  display: grid;
  place-items: center;
  padding: 24px;
  text-align: center;
}

.code {
  font-family: var(--mono);
  font-size: 13px;
  letter-spacing: .2em;
  color: var(--accent);
  text-transform: uppercase;
}

h1 {
  margin: 14px 0 10px;
  font-size: clamp(32px, 5vw, 44px);
  font-weight: 800;
  letter-spacing: -.035em;
}

p {
  color: var(--muted);
  max-width: 26rem;
  margin: 0 auto 26px;
  line-height: 1.7;
}

.button {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 11px 18px;
  border-radius: var(--radius-sm);
  background: var(--accent);
  color: var(--accent-ink);
  font-weight: 600;
  font-size: 14px;
  text-decoration: none;
  transition: background .16s, transform .14s;
}

.button:hover { background: #8fe6b4; transform: translateY(-1px); }
.button:active { transform: translateY(1px); }
</style>
</head>
<body>
<div class="wrap">
  <div class="rise">
    <div class="code">404</div>
    <h1>That page doesn't exist</h1>
    <p>The link may be wrong, or the page may have moved. Head back to the homepage to keep going.</p>
    <a class="button" href="/">Back to Content Delivery</a>
  </div>
</div>
</body>
</html>`,
    {
      status: 404,
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}