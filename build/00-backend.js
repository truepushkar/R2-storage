const VERSION = "4.0.0";
const BUCKET_NAME = "api";
const COOKIE_NAME = "session";

const PUBLIC_UPLOAD_PATH = "/public/upload";
const PUBLIC_PREFIX = "/f/";
const PUBLIC_EXPIRY = "7d";
const PUBLIC_MAX_BYTES = 100 * 1024 * 1024;

/* Types that must never render inline from this origin. */
const UNSAFE_INLINE_TYPES = [
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/xml",
  "application/xml",
  "text/javascript",
  "application/javascript",
  "application/x-javascript",
];

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

      if (
        url.pathname === PUBLIC_UPLOAD_PATH &&
        (request.method === "PUT" || request.method === "POST")
      ) {
        return await publicUpload(request, env, url);
      }

      if (
        url.pathname.startsWith(PUBLIC_PREFIX) &&
        (request.method === "GET" || request.method === "HEAD")
      ) {
        const id = decodeURIComponent(url.pathname.slice(PUBLIC_PREFIX.length));

        const wantsBytes =
          url.searchParams.has("raw") || url.searchParams.has("download");

        const wantsPage =
          request.method === "GET" &&
          !wantsBytes &&
          (request.headers.get("Accept") || "").includes("text/html");

        return wantsPage
          ? await publicPreview(request, env, id, url)
          : await publicDownload(request, env, id);
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
    visibility: "private",
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
      visibility: "private",
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
   PUBLIC UPLOAD
   ============================================================ */

function publicUploadsEnabled(env) {
  return String(env.PUBLIC_UPLOADS ?? "true").toLowerCase() !== "false";
}

function safeServeType(contentType) {
  const base = String(contentType || "")
    .split(";")[0]
    .trim()
    .toLowerCase();

  if (UNSAFE_INLINE_TYPES.includes(base)) return "application/octet-stream";
  return contentType || "application/octet-stream";
}

function mustDownload(contentType) {
  const base = String(contentType || "")
    .split(";")[0]
    .trim()
    .toLowerCase();

  return UNSAFE_INLINE_TYPES.includes(base);
}

async function publicUpload(request, env, url) {
  if (!publicUploadsEnabled(env)) {
    return json({ error: { message: "Public uploads are turned off." } }, 403);
  }

  const declared = Number(request.headers.get("Content-Length") || "0");

  if (declared > PUBLIC_MAX_BYTES) {
    return json(
      {
        error: {
          message: `File is too large. The limit is ${formatBytes(
            PUBLIC_MAX_BYTES
          )}.`,
          max_bytes: PUBLIC_MAX_BYTES,
        },
      },
      413
    );
  }

  const requestType = request.headers.get("Content-Type") || "";

  let body;
  let filename;
  let declaredType;
  let size;

  if (requestType.toLowerCase().includes("multipart/form-data")) {
    const form = await request.formData();
    const file = form.get("file");

    if (!(file instanceof File)) {
      return json({ error: { message: 'Missing "file" field.' } }, 400);
    }

    if (file.size > PUBLIC_MAX_BYTES) {
      return json(
        {
          error: {
            message: `File is too large. The limit is ${formatBytes(
              PUBLIC_MAX_BYTES
            )}.`,
            max_bytes: PUBLIC_MAX_BYTES,
          },
        },
        413
      );
    }

    body = file.stream();
    filename = sanitizeFilename(file.name || "file");
    declaredType = file.type || "application/octet-stream";
    size = file.size;
  } else {
    if (!request.body) {
      return json({ error: { message: "Request body is empty." } }, 400);
    }

    /* R2 needs a known length for a streamed body, and without one the
       size cap is unenforceable. Reject chunked uploads here. */
    if (!declared) {
      return json({ error: { message: "Content-Length is required." } }, 411);
    }

    body = request.body;
    filename = sanitizeFilename(
      url.searchParams.get("filename") ||
        request.headers.get("X-Filename") ||
        "file"
    );
    declaredType = requestType || "application/octet-stream";
    size = declared;
  }

  const storedType = safeServeType(declaredType);
  const id = generateId();
  const key = `files/${id}`;
  const uploadedAt = Date.now();
  const expiresAt = uploadedAt + EXPIRATIONS[PUBLIC_EXPIRY] * 1000;

  await env.BUCKET.put(key, body, {
    httpMetadata: {
      contentType: storedType,
      contentDisposition: buildContentDisposition(
        filename,
        mustDownload(declaredType)
      ),
      cacheControl: "public, max-age=31536000, immutable",
    },
    customMetadata: {
      originalName: filename,
      contentType: storedType,
      size: String(size),
      uploadedAt: String(uploadedAt),
      expiresAt: String(expiresAt),
      visibility: "public",
      source: "public-upload",
    },
  });

  return json(
    {
      object: "file",
      status: "complete",
      id,
      name: filename,
      size,
      content_type: storedType,
      uploaded_at: new Date(uploadedAt).toISOString(),
      expires_at: new Date(expiresAt).toISOString(),
      url: `${url.origin}${PUBLIC_PREFIX}${encodeURIComponent(id)}`,
      download_url: `${url.origin}${PUBLIC_PREFIX}${encodeURIComponent(
        id
      )}?download=1`,
    },
    201
  );
}

/* ============================================================
   PUBLIC DOWNLOAD
   ============================================================ */

async function publicDownload(request, env, id) {
  const isHead = request.method === "HEAD";

  const missing = () =>
    isHead
      ? new Response(null, {
          status: 404,
          headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
        })
      : json({ error: { message: "File not found." } }, 404);

  if (!id || id.includes("/") || id.includes("\\")) return missing();

  const key = `files/${id}`;

  const object = isHead
    ? await env.BUCKET.head(key)
    : await env.BUCKET.get(key, { range: request.headers });

  /* Private files stay private, even if someone guesses this route. */
  if (!object || object.customMetadata?.visibility !== "public") {
    return missing();
  }

  if (isExpired(object)) {
    await env.BUCKET.delete(key);

    return isHead
      ? new Response(null, {
          status: 410,
          headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
        })
      : json({ error: { message: "This link has expired." } }, 410);
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "public, max-age=31536000, immutable");

  const storedType = object.customMetadata?.contentType || "";
  const filename = sanitizeFilename(object.customMetadata?.originalName || id);
  const forced = mustDownload(storedType);
  const asked = new URL(request.url).searchParams.has("download");

  headers.set("Content-Type", safeServeType(storedType));
  headers.set(
    "Content-Disposition",
    buildContentDisposition(filename, forced || asked)
  );

  if (typeof object.size === "number") {
    headers.set("Content-Length", String(object.size));
  }

  let status = 200;

  if (!isHead && object.range && typeof object.range.offset === "number") {
    const start = object.range.offset;
    const end = start + object.range.length - 1;
    headers.set("Content-Range", `bytes ${start}-${end}/${object.size}`);
    status = 206;
  }

  return new Response(isHead ? null : object.body, {
    status,
    headers: {
      ...Object.fromEntries(headers.entries()),
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
    },
  });
}

/* ============================================================
   PUBLIC PREVIEW
   ============================================================ */

async function publicPreview(request, env, id, url) {
  if (!id || id.includes("/") || id.includes("\\")) return notFoundPage();

  const key = `files/${id}`;
  const object = await env.BUCKET.head(key);

  if (!object || object.customMetadata?.visibility !== "public") {
    return notFoundPage();
  }

  if (isExpired(object)) {
    await env.BUCKET.delete(key);
    return expiredPage();
  }

  const metadata = object.customMetadata || {};
  const expiresAt = Number(metadata.expiresAt);

  return previewPage({
    id,
    name: metadata.originalName || id,
    type: metadata.contentType || "application/octet-stream",
    size: Number(object.size || metadata.size || 0),
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
  });
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

    const isPublic = metadata.visibility === "public";

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
      visibility: isPublic ? "public" : "private",
      public_url: isPublic ? `/f/${encodeURIComponent(id)}` : null,
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
  let publicFiles = 0;

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
      if (metadata.visibility === "public") publicFiles++;
      bytes += Number(object.size || metadata.size || 0);
    }

    cursor = result.truncated ? result.cursor : undefined;
  } while (cursor);

  return json({
    object: "stats",
    files,
    public_files: publicFiles,
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

function htmlEscape(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function relativeTime(timestamp) {
  if (!timestamp) return "no expiry";

  const when = typeof timestamp === "number" ? timestamp : Date.parse(String(timestamp));
  if (!Number.isFinite(when)) return "no expiry";

  const diff = when - Date.now();
  if (diff <= 0) return "expired";

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);

  if (hours < 1) return `expires in ${Math.max(1, minutes)} min`;
  if (hours < 48) return `expires in ${hours} h`;
  return `expires in ${Math.floor(hours / 24)} d`;
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