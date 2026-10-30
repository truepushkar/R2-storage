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

/* ============================================================
   SHARED SHELL
   ============================================================ */

const FAVICON =
  '<link rel="icon" href="data:image/svg+xml,' +
  '%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 32 32%27%3E' +
  '%3Crect width=%2732%27 height=%2732%27 fill=%27%230a0b0c%27/%3E' +
  '%3Ccircle cx=%2716%27 cy=%2716%27 r=%276.5%27 fill=%27none%27 stroke=%27%23ffb000%27 stroke-width=%272%27/%3E' +
  '%3Cpath d=%27M16 4v5M16 23v5M4 16h5M23 16h5%27 stroke=%27%23ffb000%27 stroke-width=%272%27 stroke-linecap=%27round%27/%3E' +
  '%3C/svg%3E">';

const FONTS =
  '<link rel="preconnect" href="https://fonts.googleapis.com">' +
  '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
  '<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,400..900&amp;family=IBM+Plex+Mono:wght@400;500&amp;display=swap" rel="stylesheet">';

const JK_STYLE = ":root{\n  --glass:#0a0b0c; --glass-2:#101113; --glass-3:#16181b;\n  --amber:#ffb000; --amber-dim:#c98a05; --amber-16:rgba(255,176,0,.16); --amber-30:rgba(255,176,0,.30); --amber-60:rgba(255,176,0,.60);\n  --ink:#eceded; --ink-2:#b9bcc0; --mute:#8b9096;\n  --hair:rgba(255,255,255,.09); --hair-2:rgba(255,255,255,.05);\n  --bad:#ff6b5e;\n  --f:\"Archivo\",\"Segoe UI\",system-ui,sans-serif;\n  --m:\"IBM Plex Mono\",ui-monospace,Menlo,Consolas,monospace;\n  color-scheme:dark;\n}\n*[hidden]{display:none!important}\n*{box-sizing:border-box}\nhtml{scroll-behavior:smooth;-webkit-text-size-adjust:100%}\nbody{margin:0;background:var(--glass);color:var(--ink);font:400 16px/1.6 var(--f);font-stretch:88%;-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column}\n::selection{background:var(--amber);color:#0a0b0c}\n:focus-visible{outline:2px solid var(--amber);outline-offset:3px}\n*{scrollbar-width:thin;scrollbar-color:#3a3d42 transparent}\n::-webkit-scrollbar{width:10px;height:10px}\n::-webkit-scrollbar-thumb{background:#3a3d42;border:3px solid var(--glass)}\n::-webkit-scrollbar-thumb:hover{background:var(--amber-dim)}\na{color:inherit;text-decoration:none}\np{margin:0}\nimg{max-width:100%}\nh1,h2,h3{margin:0;font-weight:800;font-stretch:76%;letter-spacing:-.005em;line-height:1.02;text-wrap:balance}\n.skip{position:absolute;left:-9999px;top:6px;z-index:99;background:var(--amber);color:#0a0b0c;padding:8px 14px;font-weight:700;font-stretch:80%}\n.skip:focus{left:8px}\n.mono{font-family:var(--m);font-variant-numeric:tabular-nums;font-size:13px;letter-spacing:-.01em}\n.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n\n/* ---------- bar ---------- */\n.bar{position:sticky;top:0;z-index:40;background:color-mix(in srgb,var(--glass) 92%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--hair)}\n.bar-in{max-width:1240px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:20px}\n.mark{display:flex;align-items:center;gap:11px;font-weight:800;font-stretch:74%;text-transform:uppercase;letter-spacing:.14em;font-size:13px;white-space:nowrap}\n.mark i{width:24px;height:24px;display:grid;place-items:center;background:var(--amber);color:#0a0b0c;border-radius:2px;flex:none}\n.bar nav{display:flex;gap:2px;margin-left:auto}\n.bar nav a{padding:7px 11px;font-size:12px;font-stretch:76%;text-transform:uppercase;letter-spacing:.12em;font-weight:700;color:var(--mute);border-radius:2px;transition:color .15s,background .15s}\n.bar nav a:hover{color:var(--ink);background:var(--glass-2)}\n.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;height:38px;padding:0 16px;border:1px solid var(--hair);background:var(--glass-2);color:var(--ink);font:700 12px/1 var(--f);font-stretch:74%;text-transform:uppercase;letter-spacing:.12em;border-radius:2px;cursor:pointer;transition:background .15s,color .15s,border-color .15s,transform .12s;white-space:nowrap;text-decoration:none}\n.btn:hover{border-color:var(--amber-60);color:#fff}\n.btn:active{transform:translateY(1px)}\n.btn:disabled{opacity:.5;cursor:default}\n.btn.pri{background:var(--amber);border-color:var(--amber);color:#0a0b0c}\n.btn.pri:hover{background:#ffc23d;color:#0a0b0c}\n.btn.gh{background:transparent}\n.btn.sm{height:30px;padding:0 11px;font-size:10.5px}\n.btn.dng{background:rgba(255,107,94,.1);border-color:rgba(255,107,94,.35);color:var(--bad)}\n.btn.dng:hover{border-color:var(--bad);color:#fff}\n\n/* ---------- lanes ---------- */\nmain{flex:1}\n.sheet{max-width:1240px;margin:0 auto;padding:0 20px;min-width:0}\n.lane{display:grid;grid-template-columns:88px minmax(0,1fr)}\n.lane>*:first-child{border-right:1px solid var(--hair)}\n.gun{position:relative;padding:34px 14px 0 0;text-align:right;overflow:hidden}\n.gun b{display:block;font-family:var(--m);font-size:11px;font-weight:500;color:var(--mute);letter-spacing:.06em}\n.gun .tick{position:absolute;right:-4px;width:7px;height:1px;background:var(--amber-60)}\n.body{padding:34px 0 0 30px;min-width:0}\n.lane+.lane .gun,.lane+.lane .body{border-top:1px solid var(--hair)}\n.plate-wrap{padding:22px 0 0 30px;min-width:0}\n.sec-h{font-size:clamp(30px,3.6vw,48px);text-transform:uppercase;letter-spacing:-.01em;font-stretch:72%}\n.sec-p{color:var(--ink-2);max-width:58ch;margin-top:14px;font-size:16px;font-stretch:94%;line-height:1.6}\n.sec-p b{color:var(--ink);font-weight:600}\n.sec-p code{font-family:var(--m);font-size:.86em;color:var(--amber)}\n\n/* ---------- amber plate ---------- */\n.plate{position:relative;background:var(--amber);color:#0a0b0c;overflow:hidden}\n.plate-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 20px;border-bottom:1px solid rgba(10,11,12,.22);font-stretch:74%;text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:800}\n.plate-head .r{display:flex;gap:18px;opacity:.72}\n.plate h1{font-size:clamp(50px,8.6vw,112px);line-height:.84;letter-spacing:-.015em;font-weight:800;font-stretch:70%;padding:26px 20px 0;text-transform:uppercase}\n.plate h1 span{display:block}\n.plate .lede{padding:20px 20px 0;max-width:44ch;font-size:16.5px;font-weight:500;color:#231a05;font-stretch:92%;line-height:1.45}\n\n/* ---------- drop field ---------- */\n.field{position:relative;margin:26px 20px 0;background:var(--glass);color:var(--ink);border:1px solid rgba(10,11,12,.35);box-shadow:inset 0 0 0 1px rgba(255,176,0,.12)}\n.field .head{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:11px 14px;border-bottom:1px solid var(--hair)}\n.field .head span{font-family:var(--m);font-size:11px;color:var(--mute);letter-spacing:.04em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.drop{position:relative;display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:20px;padding:26px 20px;cursor:pointer;background:var(--glass)}\n.drop:hover,.drop.over{background:#0f1113}\n.drop input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer}\n.drop .leds{display:grid;grid-template-columns:repeat(2,7px);gap:7px;justify-items:center}\n.drop .leds i{width:7px;height:7px;background:rgba(255,255,255,.14);border-radius:50%;transition:background .2s}\n.drop.over .leds i{background:var(--amber);box-shadow:0 0 10px var(--amber-60)}\n.drop .say{min-width:0}\n.drop .say b{display:block;font-stretch:74%;text-transform:uppercase;letter-spacing:.1em;font-size:17px;font-weight:800;color:#fff}\n.drop .say em{font-style:normal;color:var(--mute);font-size:14px;letter-spacing:0}\n.drop .go{font-stretch:74%;text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:800;color:var(--amber);border:1px solid var(--amber-30);padding:9px 14px;border-radius:2px;white-space:nowrap}\n.facts{display:flex;flex-wrap:wrap;border-top:1px solid var(--hair);background:#0c0d0f}\n.facts span{flex:1 1 auto;padding:10px 14px;font-family:var(--m);font-size:11px;color:var(--mute);letter-spacing:.03em;border-right:1px solid var(--hair);white-space:nowrap}\n.facts span:last-child{border-right:0}\n.facts b{color:var(--amber);font-weight:500}\n.facts .lock{display:inline-flex;align-items:center;gap:5px}\n.facts .lock svg{width:10px;height:10px;flex:none}\n\n/* ---------- queue + links ---------- */\n.queue{display:grid}\n.q{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:center;padding:12px 14px;border-top:1px solid var(--hair-2);animation:rise .4s cubic-bezier(.16,1,.3,1) both}\n.q .nm{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.q .sub{font-family:var(--m);font-size:11px;color:var(--mute);margin-top:3px;display:flex;gap:10px;align-items:center}\n.q .meter{width:120px;height:2px;background:rgba(255,255,255,.1)}\n.q .meter i{display:block;height:100%;width:0;background:var(--amber);transition:width .25s}\n.q .err{grid-column:1/-1;color:var(--bad);font-size:13px;font-family:var(--m)}\n@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}\n.links-panel{border-top:1px solid var(--hair)}\n.links-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 14px;border-bottom:1px solid var(--hair-2)}\n.links-head b{font-stretch:74%;text-transform:uppercase;letter-spacing:.12em;font-size:11px}\n.links-head em{font-style:normal;color:var(--mute);font-family:var(--m);font-size:11px;margin-left:10px;text-transform:none;letter-spacing:0}\n.slip{display:grid;grid-template-columns:1fr auto;align-items:center;gap:12px;padding:11px 14px;border-top:1px solid var(--hair-2);animation:rise .4s cubic-bezier(.16,1,.3,1) both}\n.slip:first-child{border-top:0}\n.slip .nm{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.slip .sub{font-family:var(--m);font-size:11px;color:var(--mute);margin-top:3px}\n.slip .sub b{color:var(--amber);font-weight:500}\n.acts{display:flex;gap:4px;flex:none}\n.ib{width:30px;height:30px;display:grid;place-items:center;border:1px solid var(--hair);background:transparent;color:var(--ink-2);border-radius:2px;cursor:pointer;transition:.15s;flex:none}\n.ib:hover{color:var(--amber);border-color:var(--amber-60)}\n.ib svg{width:15px;height:15px}\n\n/* ---------- fixed-term notice (public) ---------- */\n.term{margin-top:26px;border-top:1px solid var(--hair);border-bottom:1px solid var(--hair);background:rgba(255,176,0,.05);display:grid;grid-template-columns:88px minmax(0,1fr) auto;align-items:stretch}\n.term .t{font-family:var(--m);font-size:13px;font-weight:500;padding:14px;border-right:1px solid var(--hair);color:var(--amber);display:flex;align-items:center}\n.term .d{padding:14px 16px;font-family:var(--m);font-size:12px;color:var(--ink-2);line-height:1.5;display:flex;align-items:center}\n.term .d b{color:var(--amber);font-weight:500}\n.term .k{font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--amber);padding:14px 16px;display:flex;align-items:center;gap:6px;border-left:1px solid var(--hair);white-space:nowrap}\n.term .k svg{width:11px;height:11px}\n\n/* ---------- footer / toast ---------- */\nfooter{border-top:1px solid var(--hair);margin-top:0}\n.foot{max-width:1240px;margin:0 auto;padding:20px;display:flex;flex-wrap:wrap;gap:14px 26px;align-items:center;font-family:var(--m);font-size:11px;color:var(--mute);letter-spacing:.02em}\n.foot a:hover{color:var(--amber)}\n.foot .sp{margin-left:auto}\n.toast{position:fixed;left:50%;bottom:22px;transform:translate(-50%,16px);opacity:0;pointer-events:none;background:var(--amber);color:#0a0b0c;padding:10px 16px;font:700 11px/1 var(--f);font-stretch:74%;text-transform:uppercase;letter-spacing:.12em;transition:.22s cubic-bezier(.16,1,.3,1);z-index:70;border-radius:2px;max-width:90vw}\n.toast.on{opacity:1;transform:translate(-50%,0)}\n.toast.bad{background:var(--bad);color:#fff}\n\n/* ---------- schedule ---------- */\n.sched{margin-top:26px;border-top:1px solid var(--hair)}\n.sr{position:relative;display:grid;grid-template-columns:88px minmax(0,1fr) 150px;align-items:center;gap:0;border-bottom:1px solid var(--hair);background:transparent;width:100%;text-align:left;padding:0;color:inherit;font:inherit;cursor:pointer;transition:background .15s;border-left:0;border-right:0;border-top:0}\n.sr:hover{background:var(--glass-2)}\n.sr .t{font-family:var(--m);font-size:13px;font-weight:500;padding:11px 14px;border-right:1px solid var(--hair);color:var(--ink);letter-spacing:.02em}\n.sr .r{padding:0 16px;position:relative;height:40px;display:flex;align-items:center;overflow:hidden}\n.sr .r svg{width:100%;height:20px;overflow:visible}\n.sr .r .rail-line{stroke:var(--amber-30);stroke-width:1}\n.sr .r .rail-mark{stroke:var(--amber);stroke-width:1.25;fill:none}\n.sr[aria-pressed=\"true\"]{background:var(--amber-16)}\n.sr[aria-pressed=\"true\"] .r .rail-line{stroke:var(--amber)}\n.sr[aria-pressed=\"true\"] .t{color:var(--amber)}\n.sr .d{font-family:var(--m);font-size:11px;color:var(--mute);padding:0 16px 0 0;text-align:right;letter-spacing:.02em;position:relative;z-index:1;background:var(--glass);height:100%;display:flex;align-items:center;justify-content:flex-end}\n.sr:hover .d{background:var(--glass-2)}\n.sr[aria-pressed=\"true\"] .d{background:#1d1a0f;color:var(--ink-2)}\n.readout{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 18px;padding:16px 0 0;font-family:var(--m);font-size:12px;color:var(--mute)}\n.readout b{color:var(--amber);font-weight:500}\n.readout .sep{width:1px;height:12px;background:var(--hair)}\n\n/* ---------- api ---------- */\n.api{margin-top:26px;border:1px solid var(--hair);background:var(--glass-2);min-width:0;overflow:hidden}\n.tabs{display:flex;overflow-x:auto;border-bottom:1px solid var(--hair);scrollbar-width:none}\n.tabs::-webkit-scrollbar{display:none}\n.tab{position:relative;display:inline-flex;align-items:center;gap:10px;padding:12px 16px;background:transparent;border:0;border-right:1px solid var(--hair);color:var(--mute);font:700 11px/1 var(--f);font-stretch:74%;text-transform:uppercase;letter-spacing:.12em;cursor:pointer;white-space:nowrap;transition:.15s}\n.tab .verb{font-family:var(--m);font-size:10px;letter-spacing:0;padding:3px 5px;border:1px solid var(--hair);color:var(--ink-2)}\n.tab:hover{color:var(--ink);background:var(--glass-3)}\n.tab[aria-selected=\"true\"]{color:var(--amber);background:var(--glass)}\n.tab[aria-selected=\"true\"] .verb{border-color:var(--amber-60);color:var(--amber)}\n.tab[aria-selected=\"true\"]:after{content:\"\";position:absolute;left:0;right:0;bottom:-1px;height:2px;background:var(--amber)}\n.pane{padding:20px 18px;min-width:0}\n.req{display:grid;gap:16px;min-width:0}\n.req>*{min-width:0}\n.lbl{font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute);margin-bottom:7px}\npre{margin:0;padding:15px 16px;background:var(--glass);border:1px solid var(--hair);overflow-x:auto;font:13px/1.65 var(--m);color:var(--ink-2);tab-size:2}\npre .c{color:#6f747a}\npre .s{color:#e8e9ea}\npre .a{color:var(--amber)}\npre .n{color:#c9a76b}\n\n/* ---------- patch / forms ---------- */\n.patch{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr);margin-top:26px;border:1px solid var(--hair)}\n.patch .l{padding:24px 22px;border-right:1px solid var(--hair);background:var(--glass-2);min-width:0}\n.patch .r{padding:24px 22px;min-width:0}\n.patch h3{font-size:24px;text-transform:uppercase;font-stretch:72%;letter-spacing:.01em}\n.patch p{color:var(--ink-2);font-size:14px;margin-top:8px;max-width:38ch}\n.fld{margin-top:18px}\n.inp{display:flex;gap:8px}\ninput[type=password],input[type=text],input[type=search],select{width:100%;min-width:0;height:40px;padding:0 12px;background:var(--glass);border:1px solid var(--hair);color:var(--ink);font:13px var(--m);border-radius:2px}\ninput:focus,select:focus{outline:none;border-color:var(--amber);box-shadow:0 0 0 1px var(--amber)}\ninput::placeholder{color:#5d6268}\nselect{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mute) 50%),linear-gradient(135deg,var(--mute) 50%,transparent 50%);background-position:calc(100% - 15px) 17px,calc(100% - 10px) 17px;background-size:5px 5px;background-repeat:no-repeat;padding-right:32px}\n.err{display:none;margin-top:12px;padding:9px 11px;border:1px solid rgba(255,107,94,.4);color:var(--bad);font:12px var(--m);background:rgba(255,107,94,.06)}\n.err.on{display:block}\n.cats{list-style:none;padding:0;margin:16px 0 0;border-top:1px solid var(--hair)}\n.cats li{display:grid;grid-template-columns:1fr auto;gap:12px;padding:9px 0;border-bottom:1px solid var(--hair-2);font-size:14px;color:var(--ink-2)}\n.cats li b{color:var(--ink);font-weight:600}\n.cats li span{font-family:var(--m);font-size:11px;color:var(--mute)}\n\n/* ---------- doc page ---------- */\n.doc{max-width:920px;margin:0 auto;padding:0 20px}\n.doc-h{padding:34px 0 0}\n.doc-h h1{font-size:clamp(32px,5vw,56px);text-transform:uppercase;letter-spacing:-.015em;font-stretch:72%}\n.doc-h p{margin-top:14px;color:var(--ink-2);max-width:62ch}\n.note{margin-top:22px;border:1px solid var(--amber-30);background:rgba(255,176,0,.05);padding:14px 16px;font-size:14px;color:var(--ink-2);display:flex;gap:12px;align-items:flex-start}\n.note svg{width:16px;height:16px;color:var(--amber);flex:none;margin-top:3px}\n.note code{font-family:var(--m);font-size:.88em;color:var(--amber)}\n.grp{margin-top:38px;font-family:var(--m);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--mute);border-bottom:1px solid var(--hair);padding-bottom:9px}\n.ep{margin-top:18px;border:1px solid var(--hair);background:var(--glass-2)}\n.ep-h{display:flex;align-items:center;gap:12px;padding:11px 16px;border-bottom:1px solid var(--hair);flex-wrap:wrap}\n.ep-h .v{font-family:var(--m);font-size:10px;font-weight:500;letter-spacing:.06em;padding:3px 6px;border:1px solid var(--hair);color:var(--ink-2);flex:none}\n.ep-h .v.put,.ep-h .v.post{border-color:var(--amber-60);color:var(--amber)}\n.ep-h .v.get{border-color:rgba(56,189,248,.5);color:#7dd3fc}\n.ep-h .v.del{border-color:rgba(255,107,94,.5);color:var(--bad)}\n.ep-h .p{font-family:var(--m);font-size:13px;color:#fff;font-weight:500}\n.ep-h .tag{margin-left:auto;font-family:var(--m);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--mute)}\n.ep-b{padding:16px}\n.ep-b p{color:var(--ink-2);font-size:14px;margin:0 0 14px}\n.ep-b p:last-child{margin-bottom:0}\n.ep-b code{font-family:var(--m);font-size:.88em;color:var(--amber);background:rgba(255,176,0,.08);padding:1px 5px;border-radius:2px}\n.ep-b .lbl:not(:first-child){margin-top:14px}\ntable.exp{width:100%;border-collapse:collapse;margin-top:16px;border:1px solid var(--hair);background:var(--glass-2);font-size:14px}\ntable.exp th{text-align:left;padding:9px 14px;font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute);border-bottom:1px solid var(--hair);font-weight:500}\ntable.exp td{padding:9px 14px;border-bottom:1px solid var(--hair-2);color:var(--ink-2)}\ntable.exp tr:last-child td{border-bottom:0}\ntable.exp td:first-child{font-family:var(--m);font-size:12.5px;color:var(--amber);width:110px}\ntable.exp td.fx{color:var(--ink);font-weight:600}\n\n/* ---------- dashboard ---------- */\n.dash{max-width:1240px;margin:0 auto;padding:22px 20px 0}\n.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--hair);background:var(--glass-2)}\n.stat{padding:16px 18px;border-right:1px solid var(--hair);min-width:0}\n.stat:last-child{border-right:0}\n.stat .k{font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute)}\n.stat .v{font-family:var(--m);font-size:24px;font-weight:500;color:var(--ink);margin-top:6px;letter-spacing:-.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.stat.am .v{color:var(--amber)}\n.up{margin-top:16px;border:1px solid var(--hair);background:var(--glass-2);padding:16px}\n.up .top{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:14px}\n.up .top .h{font-family:var(--m);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute)}\n.up .row{display:grid;grid-template-columns:minmax(0,1fr) 190px auto;gap:10px;align-items:center}\n.up input[type=file]{width:100%;min-width:0;font:12px var(--m);color:var(--ink-2);padding:8px 0}\n.up input[type=file]::file-selector-button{appearance:none;border:1px solid var(--hair);background:var(--glass);color:var(--ink);font:700 10.5px/1 var(--f);font-stretch:74%;text-transform:uppercase;letter-spacing:.1em;padding:9px 12px;border-radius:2px;cursor:pointer;margin-right:12px}\n.up input[type=file]::file-selector-button:hover{border-color:var(--amber-60);color:var(--amber)}\n#progress{font-family:var(--m);font-size:11.5px;color:var(--mute);margin-top:10px;min-height:15px}\n.files{margin-top:16px;border:1px solid var(--hair);background:var(--glass-2)}\n.files-h{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--hair)}\n.files-h .t{font-family:var(--m);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2)}\n.files-h .t em{font-style:normal;color:var(--mute);margin-left:8px}\n.filters{display:grid;grid-template-columns:minmax(0,1fr) 170px 160px;gap:8px;padding:12px 16px;border-bottom:1px solid var(--hair)}\n.bulkbar{display:none;gap:12px;align-items:center;justify-content:space-between;padding:9px 16px;border-bottom:1px solid var(--hair);background:var(--amber-16)}\n.bulkbar.on{display:flex}\n.bulkbar .n{font-family:var(--m);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--amber)}\n.tablewrap{overflow-x:auto}\ntable.files-t{width:100%;min-width:920px;border-collapse:collapse}\ntable.files-t th{text-align:left;padding:10px 14px;font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute);border-bottom:1px solid var(--hair);font-weight:500;white-space:nowrap}\ntable.files-t th.cb{width:38px;padding-left:16px}\ntable.files-t td{padding:10px 14px;border-bottom:1px solid var(--hair-2);vertical-align:middle;font-size:13.5px;color:var(--ink-2)}\ntable.files-t tr:last-child td{border-bottom:0}\ntable.files-t tr:hover td{background:rgba(255,255,255,.02)}\n.fn{display:flex;align-items:center;gap:11px;min-width:0}\n.fn .g{width:30px;height:30px;border:1px solid var(--hair);display:grid;place-items:center;color:var(--amber);flex:none;border-radius:2px}\n.fn .g svg{width:15px;height:15px}\n.fn .meta{min-width:0}\n.fn .n{font-weight:600;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:264px}\n.fn .ct{font-family:var(--m);font-size:10.5px;color:var(--mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}\n.badge{display:inline-block;margin-left:7px;font-family:var(--m);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:#7dd3fc;border:1px solid rgba(56,189,248,.4);padding:1px 5px;border-radius:2px;vertical-align:1px}\n.pill{display:inline-block;font-family:var(--m);font-size:10.5px;letter-spacing:.04em;padding:2px 7px;border-radius:2px;border:1px solid var(--hair);color:var(--ink-2);white-space:nowrap}\n.pill.warn{border-color:rgba(255,176,0,.45);color:var(--amber)}\n.pill.never{border-color:rgba(125,211,252,.4);color:#7dd3fc}\n.pill.dead{border-color:rgba(255,107,94,.4);color:var(--bad)}\n.rowact{display:flex;gap:4px;flex-wrap:nowrap}\n.mini{height:26px;padding:0 9px;border:1px solid var(--hair);background:transparent;color:var(--ink-2);font:700 10px/1 var(--f);font-stretch:74%;text-transform:uppercase;letter-spacing:.08em;border-radius:2px;cursor:pointer;transition:.15s;white-space:nowrap}\n.mini:hover{border-color:var(--amber-60);color:var(--amber)}\n.mini.dng:hover{border-color:var(--bad);color:var(--bad)}\n.empty{padding:52px 20px;text-align:center}\n.empty svg{width:26px;height:26px;color:var(--mute);margin-bottom:12px}\n.empty b{display:block;font-size:16px;color:var(--ink);font-weight:600}\n.empty p{color:var(--mute);font-size:13.5px;margin-top:5px}\ninput[type=checkbox]{width:15px;height:15px;accent-color:var(--amber);cursor:pointer;vertical-align:middle}\n\n/* ---------- modal ---------- */\n.modal{position:fixed;inset:0;z-index:90;display:none;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.72);backdrop-filter:blur(3px)}\n.modal.on{display:flex}\n.modal .card{width:100%;max-width:680px;max-height:86vh;overflow:auto;background:var(--glass-2);border:1px solid var(--amber-30);padding:20px;animation:rise .3s cubic-bezier(.16,1,.3,1) both}\n.modal .mh{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:16px}\n.modal .mh span{font-family:var(--m);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2)}\n.kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--hair)}\n.kv div{background:var(--glass);padding:11px 13px;min-width:0}\n.kv .k{font-family:var(--m);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute)}\n.kv .v{font-size:13px;color:var(--ink);margin-top:4px;word-break:break-all}\n.kv .wide{grid-column:1/-1}\n\n/* ---------- status page ---------- */\n.status{min-height:calc(100vh - 58px);display:grid;place-items:center;padding:40px 20px}\n.status .box{max-width:520px;width:100%}\n.status .code{font-family:var(--m);font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--amber);margin-bottom:14px}\n.status h1{font-size:clamp(30px,5vw,46px);text-transform:uppercase;font-stretch:72%;letter-spacing:-.015em}\n.status p{margin-top:14px;color:var(--ink-2);max-width:46ch}\n.status .a{margin-top:26px}\n\n/* ---------- preview ---------- */\n.pv{max-width:960px;margin:0 auto;padding:22px 20px 0}\n.pv-card{border:1px solid var(--hair);background:var(--glass-2)}\n.pv-h{display:flex;flex-wrap:wrap;align-items:center;gap:14px;padding:14px 16px;border-bottom:1px solid var(--hair)}\n.pv-h .g{width:34px;height:34px;border:1px solid var(--hair);display:grid;place-items:center;color:var(--amber);flex:none;border-radius:2px}\n.pv-h .g svg{width:16px;height:16px}\n.pv-h .meta{min-width:0;flex:1}\n.pv-h .n{font-weight:700;font-size:15px;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.pv-h .s{font-family:var(--m);font-size:10.5px;color:var(--mute);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.pv-h .s b{color:var(--amber);font-weight:500}\n.pv-b{padding:20px;display:grid;place-items:center;min-height:220px;background:var(--glass)}\n.pv-b img,.pv-b video{max-width:100%;max-height:70vh;display:block}\n.pv-b audio{width:100%;max-width:520px}\n.pv-b iframe{width:100%;height:72vh;border:0;background:var(--glass-2)}\n.pv-b pre{max-height:68vh;width:100%;overflow:auto;white-space:pre-wrap;word-break:break-word;border:0;background:transparent;padding:0}\n.pv-f{display:flex;gap:8px;padding:14px 16px;border-top:1px solid var(--hair)}\n.pv-f input{flex:1}\n.nopv{display:grid;place-items:center;gap:10px;text-align:center;color:var(--mute);font-size:14px;padding:30px 0}\n.nopv svg{width:24px;height:24px}\n\n/* ---------- responsive ---------- */\n@media (max-width:900px){\n  .patch{grid-template-columns:1fr}\n  .patch .l{border-right:0;border-bottom:1px solid var(--hair)}\n  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}\n  .stat:nth-child(2){border-right:0}\n  .stat:nth-child(1),.stat:nth-child(2){border-bottom:1px solid var(--hair)}\n  .up .row{grid-template-columns:1fr}\n  .filters{grid-template-columns:1fr}\n  .kv{grid-template-columns:1fr}\n}\n@media (max-width:760px){\n  .lane{grid-template-columns:44px minmax(0,1fr)}\n  .plate-wrap{padding:16px 0 0 16px}\n  .body{padding:26px 0 0 16px}\n  .plate h1{padding:20px 14px 0}\n  .plate .lede{padding:16px 14px 0;font-size:15px}\n  .field{margin:20px 14px 0}\n  .drop{grid-template-columns:1fr;gap:14px;padding:20px 14px}\n  .drop .go{justify-self:start}\n  .drop .leds{display:none}\n  .sr{grid-template-columns:60px minmax(0,1fr)}\n  .sr .d{display:none}\n  .term{grid-template-columns:1fr;border-left:0}\n  .term .t{border-right:0;border-bottom:1px solid var(--hair);font-size:15px;padding:10px 14px;justify-content:space-between}\n  .term .t:after{content:\"locked\";font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:var(--mute)}\n  .term .k{display:none}\n  .term .d{padding:12px 14px;font-size:11.5px}\n  .bar nav{display:none}\n  .bar-in{gap:10px;height:54px;padding:0 14px}\n  .mark{font-size:11px;letter-spacing:.1em;gap:8px}\n  .mark i{width:21px;height:21px}\n  .btn.gh{display:none}\n  .bar .btn.pri{margin-left:auto;height:34px;padding:0 12px;font-size:10.5px;letter-spacing:.1em}\n  .facts span{flex:1 1 calc(50% - 1px);border-right:0;border-bottom:1px solid var(--hair);font-size:10.5px;padding:9px 12px}\n  .facts span:nth-child(odd){border-right:1px solid var(--hair)}\n  .plate-head{font-size:9.5px;letter-spacing:.1em;padding:11px 14px;gap:10px}\n  .plate-head .r{gap:10px}\n  pre{font-size:11.5px;line-height:1.7}\n  .readout{font-size:11px}\n  .sec-h{font-size:clamp(26px,8vw,34px)}\n  .sheet,.dash,.doc,.pv{padding-left:14px;padding-right:14px}\n  .doc-h h1{font-size:clamp(28px,8vw,38px)}\n  .pv-b iframe{height:56vh}\n}\n.lane>*, .plate-wrap>*, .patch>*, .term>*, .mod>.card{min-width:0}\n.modal .card{min-width:0}\n\n@media (prefers-reduced-motion:reduce){\n  *{animation:none!important;transition:none!important;scroll-behavior:auto}\n}";

const HEAD = FONTS + FAVICON + "<style>" + JK_STYLE + "</style>";

const SITE_HEADER =
  '<header class="bar"><div class="bar-in">' +
  '<a class="mark" href="/"><i>' +
  '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M6 11l6-6 6 6"/></svg>' +
  "</i>Content Delivery</a>" +
  '<nav><a href="/#drop">Drop</a><a href="/#expiry">Expiry</a><a href="/docs">Docs</a><a href="/#patch">Sign in</a></nav>' +
  '<a class="btn pri" href="/dashboard">Dashboard</a>' +
  "</div></header>";

const SITE_FOOTER =
  '<footer><div class="foot">' +
  "<span>Content Delivery &mdash; Cloudflare Workers + R2</span>" +
  '<a href="/docs">API docs</a><a href="/dashboard">Dashboard</a>' +
  '<span class="sp">v' + VERSION + '</span>' +
  "</div></footer>";

function htmlPage(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}


/* ============================================================
   PUBLIC SITE
   ============================================================ */

function publicPage() {
  return htmlPage(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Content Delivery &mdash; send a file, get a link</title>
<meta name="description" content="Drop a file, get a link. Files are stored on Cloudflare R2 and delete themselves after seven days.">
${HEAD}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
${SITE_HEADER}
<main id="main">
<div class="sheet">

<div class="lane" id="drop">
  <div class="gun"><b>01</b><span class="tick" style="top:44px"></span></div>
  <div class="plate-wrap">
    <div class="plate">
      <div class="plate-head"><span>Public drop &middot; no key</span><span class="r"><span>R2 edge</span><span>7-day term</span></span></div>
      <h1><span>Send a file.</span><span>Get a link.</span></h1>
      <p class="lede">Anyone with the link can open it in a browser or pull the bytes down. Seven days later it is deleted, and nobody has to clean up.</p>

      <div class="field">
        <div class="head"><span>/public/upload</span><span>100 MB per file</span></div>
        <div class="drop" id="drop-target">
          <input id="file-input" type="file" multiple aria-label="Choose files">
          <div class="leds" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
          <div class="say"><b>Drop files here</b><em>or paste from the clipboard &mdash; the link appears right here</em></div>
          <span class="go">Choose files</span>
        </div>
        <div class="facts">
          <span class="lock"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><b>7 days</b> fixed</span>
          <span><b>100 MB</b> per file</span>
          <span><b>Any</b> file type</span>
          <span><b>No</b> account needed</span>
        </div>
        <div id="queue" class="queue" aria-live="polite"></div>
        <div id="links-panel" class="links-panel" hidden>
          <div class="links-head"><div><b>Your links</b><em>kept in this browser only</em></div><button id="clear-links" class="btn sm" type="button">Clear all</button></div>
          <div id="links"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="lane" id="expiry">
  <div class="gun"><b>02</b><span class="tick" style="top:44px"></span></div>
  <div class="body">
    <h2 class="sec-h">Public drops have one term</h2>
    <p class="sec-p">Every file uploaded through the public drop is deleted after <b>seven days</b>. It is not a setting and there is no control for it: the Worker assigns the term and sweeps whatever has passed. <b>The private API is where you choose.</b></p>

    <div class="term">
      <div class="t">7d</div>
      <div class="d">Fixed term for <b>/public/upload</b>. Nobody can extend it from the browser, and nothing is kept past it.</div>
      <div class="k"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>Locked</div>
    </div>
  </div>
</div>

<div class="lane" id="private">
  <div class="gun"><b>03</b><span class="tick" style="top:44px"></span></div>
  <div class="body">
    <h2 class="sec-h">With a key, you pick the lifetime</h2>
    <p class="sec-p">The private API takes any of these at upload. A scheduled sweep clears what has expired, and a download past its date deletes the object on the spot.</p>
    <div class="sched" id="sched" role="group" aria-label="Lifetimes available to the private API"></div>
    <div class="readout"><span>Upload now &rarr; deletes <b id="ro-date">&mdash;</b></span><span class="sep"></span><span id="ro-note">&nbsp;</span></div>
  </div>
</div>

<div class="lane" id="api">
  <div class="gun"><b>04</b><span class="tick" style="top:44px"></span></div>
  <div class="body">
    <h2 class="sec-h">One HTTP call, no client library</h2>
    <p class="sec-p">The dashboard is a convenience. Every action in it is a plain request you can send from a terminal, a script, or anything that speaks HTTP. Range requests work, so video seeks and downloads resume.</p>
    <div class="api">
      <div class="tabs" role="tablist" id="tabs"></div>
      <div class="pane" id="pane"></div>
    </div>
  </div>
</div>

<div class="lane" id="patch">
  <div class="gun"><b>05</b><span class="tick" style="top:44px"></span></div>
  <div class="body">
    <h2 class="sec-h">Owner sign-in</h2>
    <p class="sec-p">Your API key opens the dashboard and every private endpoint. It is the only credential in the system.</p>
    <div class="patch">
      <div class="l">
        <h3 style="font-size:18px">Patch in</h3>
        <p>Paste the key you set with <span class="mono" style="color:var(--amber)">wrangler secret put API_KEY</span>.</p>
        <form id="login" novalidate style="margin-top:2px" action="/auth/login" method="post">
          <div class="fld">
            <label class="lbl" for="key">API key</label>
            <div class="inp">
              <input id="key" type="password" autocomplete="current-password" placeholder="paste key">
              <button id="reveal" class="ib" type="button" aria-label="Show key" style="height:40px;width:40px">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/></svg>
              </button>
            </div>
          </div>
          <div class="err" id="login-err" role="alert"></div>
          <button class="btn pri" type="submit" style="width:100%;margin-top:14px;height:40px" id="login-btn"><span id="login-label">Sign in</span></button>
        </form>
      </div>
      <div class="r">
        <h3 style="font-size:18px;color:var(--ink-2)">Behind the key</h3>
        <ul class="cats">
          <li><b>Every file, searchable</b><span>name &middot; type &middot; size</span></li>
          <li><b>Storage totals</b><span>bytes &middot; count &middot; expired</span></li>
          <li><b>Bulk delete</b><span>1000 per call</span></li>
          <li><b>Per-file metadata</b><span>etag &middot; expiry &middot; url</span></li>
        </ul>
      </div>
    </div>
  </div>
</div>

</div>
</main>
${SITE_FOOTER}
<div class="toast" id="toast" role="status"></div>
<script>(function () {
  var MAX_BYTES = 100 * 1024 * 1024;
  var STORE = "cdn.links.v6";

  var ICON = {
    down: '<path d="M12 4v12m0 0 4-4m-4 4-4-4M4 20h16"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="1"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    out: '<path d="M14 4h6v6m0-6L10 14M18 14v5H5V5h5"/>'
  };

  function icon(name) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + ICON[name] + "</svg>";
  }

  function esc(value) {
    var node = document.createElement("div");
    node.textContent = String(value == null ? "" : value);
    return node.innerHTML;
  }

  function fmtBytes(bytes) {
    bytes = Number(bytes) || 0;
    if (!bytes) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }

  function toast(message, bad) {
    var node = document.getElementById("toast");
    node.textContent = message;
    node.className = "toast on" + (bad ? " bad" : "");
    clearTimeout(window.__toast);
    window.__toast = setTimeout(function () { node.className = "toast"; }, 2600);
  }

  function copy(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        function () { toast("Link copied"); },
        function () { window.prompt("Copy this link", value); }
      );
    } else {
      window.prompt("Copy this link", value);
    }
  }

  function left(iso) {
    if (!iso) return "no expiry";
    var diff = Date.parse(iso) - Date.now();
    if (diff <= 0) return "expired";
    var minutes = Math.floor(diff / 6e4);
    var hours = Math.floor(minutes / 60);
    var days = Math.floor(hours / 24);
    if (days >= 2) return days + "d " + (hours % 24) + "h left";
    if (hours >= 1) return hours + "h " + (minutes % 60) + "m left";
    return minutes + "m left";
  }

  /* ---------- lifetime schedule: private API only ---------- */

  var LIFETIMES = [
    ["1h", 3600e3, "one working session"],
    ["6h", 6 * 3600e3, "overnight"],
    ["12h", 12 * 3600e3, "half a day"],
    ["1d", 864e5, "a day"],
    ["3d", 3 * 864e5, "a weekend"],
    ["7d", 7 * 864e5, "a week"],
    ["30d", 30 * 864e5, "a month"],
    ["90d", 90 * 864e5, "a quarter"],
    ["never", null, "until deleted"]
  ];

  var sched = document.getElementById("sched");
  var readoutDate = document.getElementById("ro-date");
  var readoutNote = document.getElementById("ro-note");

  function rail(ms, selected) {
    var out = '<svg viewBox="-4 0 108 20" preserveAspectRatio="none" aria-hidden="true">';
    out += '<line class="rail-line" x1="0" y1="10" x2="100" y2="10"/>';

    if (ms === null) {
      out += '<line class="rail-mark" x1="0" y1="10" x2="100" y2="10"/>';
      out += '<circle class="rail-mark" cx="100" cy="10" r="3.4"/>';
      return out + "</svg>";
    }

    var ratio = Math.log(ms / 3600e3) / Math.log(2160);
    var width = Math.max(6, Math.min(100, ratio * 100));

    out += '<line class="rail-mark" x1="0" y1="4" x2="0" y2="16"/>';
    out += '<line class="rail-mark" x1="0" y1="10" x2="' + width + '" y2="10"/>';

    if (selected) {
      out += '<line class="rail-mark" x1="0" y1="7" x2="' + width + '" y2="7"/>';
      out += '<line class="rail-mark" x1="0" y1="13" x2="' + width + '" y2="13"/>';
    }

    out += '<line class="rail-mark" x1="' + width + '" y1="4" x2="' + width + '" y2="16"/>';
    return out + "</svg>";
  }

  function readout(ms) {
    if (ms === null) {
      readoutDate.textContent = "never";
      readoutNote.textContent = "stays until you delete it";
      return;
    }
    readoutDate.textContent = new Date(Date.now() + ms).toISOString().replace("T", " ").slice(0, 16) + " UTC";
    readoutNote.textContent = "swept by the next cron run";
  }

  if (sched) {
    LIFETIMES.forEach(function (entry) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "sr";
      button.setAttribute("aria-pressed", entry[0] === "7d" ? "true" : "false");
      button.innerHTML =
        '<span class="t">' + entry[0] + "</span>" +
        '<span class="r">' + rail(entry[1], entry[0] === "7d") + "</span>" +
        '<span class="d">' + entry[2] + "</span>";
      button.addEventListener("click", function () {
        Array.prototype.forEach.call(sched.children, function (child) {
          child.setAttribute("aria-pressed", "false");
        });
        button.setAttribute("aria-pressed", "true");
        readout(entry[1]);
      });
      sched.appendChild(button);
    });
    readout(7 * 864e5);
  }
  /* ---------- api tabs ---------- */

  var NL = String.fromCharCode(10);

  function joinLines(lines) {
    return lines.join(NL);
  }

  var TABS = [
    {
      verb: "PUT",
      path: "/api/upload",
      tag: "stream in",
      request: joinLines([
        "curl -X PUT \\"" + location.origin + "/api/upload?filename=clip.mp4&expires=7d\\" \\\\",
        "  -H \\"authorization: Bearer $KEY\\" \\\\",
        "  -H \\"content-type: video/mp4\\" \\\\",
        "  --data-binary @clip.mp4"
      ]),
      response: joinLines([
        "{",
        "  \\"id\\": \\"a4e3c1...\\",",
        "  \\"name\\": \\"clip.mp4\\",",
        "  \\"size\\": 184320000,",
        "  \\"expires_at\\": \\"2026-11-06T14:43Z\\",",
        "  \\"download_url\\": \\"/api/files/a4e3c1...\\"",
        "}"
      ])
    },
    {
      verb: "PUT",
      path: "/public/upload",
      tag: "no key, fixed 7d",
      request: joinLines([
        "curl -X PUT \\"" + location.origin + "/public/upload?filename=notes.txt\\" \\\\",
        "  -H \\"content-type: text/plain\\" \\\\",
        "  --data-binary @notes.txt"
      ]),
      response: joinLines([
        "{",
        "  \\"id\\": \\"abc123...\\",",
        "  \\"name\\": \\"notes.txt\\",",
        "  \\"expires_at\\": \\"2026-11-06T14:43Z\\",",
        "  \\"url\\": \\"" + location.origin + "/f/abc123...\\"",
        "}"
      ])
    },
    {
      verb: "GET",
      path: "/api/files",
      tag: "list + search",
      request: joinLines([
        "curl \\"" + location.origin + "/api/files?search=clip&sort=size&order=desc\\" \\\\",
        "  -H \\"authorization: Bearer $KEY\\""
      ]),
      response: joinLines([
        "{",
        "  \\"data\\": [ { \\"id\\": \\"a4e3c1...\\", \\"name\\": \\"clip.mp4\\", \\"size\\": 184320000 } ],",
        "  \\"pagination\\": { \\"cursor\\": null, \\"has_more\\": false },",
        "  \\"count\\": 1",
        "}"
      ])
    },
    {
      verb: "GET",
      path: "/api/files/:id",
      tag: "range bytes",
      request: joinLines([
        "curl \\"" + location.origin + "/api/files/a4e3c1...\\" \\\\",
        "  -H \\"range: bytes=0-1023\\" \\\\",
        "  -H \\"authorization: Bearer $KEY\\""
      ]),
      response: joinLines([
        "HTTP/1.1 206 Partial Content",
        "content-range: bytes 0-1023/184320000",
        "accept-ranges: bytes",
        "content-type: video/mp4"
      ])
    },
    {
      verb: "DEL",
      path: "/api/files",
      tag: "bulk up to 1000",
      request: joinLines([
        "curl -X DELETE \\"" + location.origin + "/api/files\\" \\\\",
        "  -H \\"authorization: Bearer $KEY\\" \\\\",
        "  -H \\"content-type: application/json\\" \\\\",
        "  --data @ids.json"
      ]),
      response: '{ "deleted": 2 }'
    }
  ];

  var tabBar = document.getElementById("tabs");
  var pane = document.getElementById("pane");

  function paint(text) {
    var out = "";
    text.split(NL).forEach(function (line) {
      var safe = esc(line);
      if (/^curl|^HTTP/.test(line)) out += '<span class="a">' + safe + "</span>" + NL;
      else if (/^\\s/.test(line)) out += '<span class="n">' + safe + "</span>" + NL;
      else out += '<span class="s">' + safe + "</span>" + NL;
    });
    return out;
  }

  function selectTab(index) {
    Array.prototype.forEach.call(tabBar.children, function (child, i) {
      child.setAttribute("aria-selected", i === index ? "true" : "false");
    });
    var tab = TABS[index];
    pane.innerHTML =
      '<div class="req"><div><div class="lbl">Request &middot; ' + esc(tab.tag) + '</div><pre>' + paint(tab.request) + "</pre></div>" +
      '<div><div class="lbl">Response</div><pre>' + paint(tab.response) + "</pre></div></div>";
  }

  if (tabBar) {
    TABS.forEach(function (tab, index) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "tab";
      button.setAttribute("role", "tab");
      button.innerHTML = '<span class="verb">' + tab.verb + "</span>" + esc(tab.path);
      button.addEventListener("click", function () { selectTab(index); });
      tabBar.appendChild(button);
    });
    selectTab(0);
  }

  /* ---------- public uploader ---------- */

  var target = document.getElementById("drop-target");
  var picker = document.getElementById("file-input");
  var queue = document.getElementById("queue");
  var panel = document.getElementById("links-panel");
  var list = document.getElementById("links");
  var waiting = [];
  var busy = false;

  function read() {
    try {
      var raw = JSON.parse(localStorage.getItem(STORE) || "[]");
      return Array.isArray(raw) ? raw : [];
    } catch (error) {
      return [];
    }
  }

  function write(entries) {
    try { localStorage.setItem(STORE, JSON.stringify(entries)); } catch (error) {}
  }

  function living(entries) {
    var now = Date.now();
    return entries.filter(function (entry) {
      return entry && entry.id && entry.url && (!entry.expires_at || Date.parse(entry.expires_at) > now);
    });
  }

  function slip(entry) {
    var row = document.createElement("div");
    row.className = "slip";
    row.innerHTML =
      '<div style="min-width:0"><div class="nm">' + esc(entry.name) + "</div>" +
      '<div class="sub">' + fmtBytes(entry.size) + ' &middot; <b>/f/' + esc(String(entry.id).slice(0, 6)) + "</b> &middot; " + left(entry.expires_at) + "</div></div>";

    var acts = document.createElement("div");
    acts.className = "acts";

    function makeAction(title, glyph, handler) {
      var node = document.createElement(handler ? "button" : "a");
      node.className = "ib";
      node.title = title;
      node.innerHTML = icon(glyph);
      if (handler) {
        node.type = "button";
        node.addEventListener("click", handler);
      } else if (title === "Open") {
        node.href = entry.url;
        node.target = "_blank";
        node.rel = "noopener";
      } else {
        node.href = entry.url + "?download=1";
        node.setAttribute("download", entry.name || "");
      }
      acts.appendChild(node);
    }

    makeAction("Open", "out");
    makeAction("Download", "down");
    makeAction("Copy link", "copy", function () { copy(entry.url); });
    makeAction("Forget", "x", function () {
      write(living(read()).filter(function (item) { return item.id !== entry.id; }));
      render();
    });

    row.appendChild(acts);
    return row;
  }

  function render() {
    var entries = living(read());
    write(entries);
    panel.hidden = !entries.length;
    list.innerHTML = "";
    entries.forEach(function (entry) { list.appendChild(slip(entry)); });
  }

  var clearButton = document.getElementById("clear-links");
  if (clearButton) {
    clearButton.addEventListener("click", function () {
      if (!confirm("Forget every saved link in this browser? The files stay online until they expire.")) return;
      write([]);
      render();
    });
  }

  picker.addEventListener("change", function () {
    enqueue(picker.files);
    picker.value = "";
  });

  ["dragenter", "dragover"].forEach(function (name) {
    target.addEventListener(name, function (event) {
      event.preventDefault();
      target.classList.add("over");
    });
  });

  ["dragleave", "drop"].forEach(function (name) {
    target.addEventListener(name, function (event) {
      event.preventDefault();
      target.classList.remove("over");
      if (name === "drop" && event.dataTransfer && event.dataTransfer.files.length) {
        enqueue(event.dataTransfer.files);
      }
    });
  });

  document.addEventListener("paste", function (event) {
    if (event.clipboardData && event.clipboardData.files.length) enqueue(event.clipboardData.files);
  });

  ["dragover", "drop"].forEach(function (name) {
    window.addEventListener(name, function (event) {
      if (!target.contains(event.target)) event.preventDefault();
    });
  });

  function enqueue(files) {
    for (var i = 0; i < files.length; i++) waiting.push(files[i]);
    pump();
  }

  function pump() {
    if (busy || !waiting.length) return;
    busy = true;
    send(waiting.shift(), function () {
      busy = false;
      pump();
    });
  }

  function send(file, done) {
    var row = document.createElement("div");
    row.className = "q";
    row.innerHTML =
      '<div style="min-width:0"><div class="nm">' + esc(file.name) + "</div>" +
      '<div class="sub"><span class="meter"><i></i></span><span class="st">queued</span></div></div>';
    queue.insertBefore(row, queue.firstChild);

    var state = row.querySelector(".st");
    var fill = row.querySelector(".meter i");

    function fail(message) {
      state.textContent = "failed";
      state.style.color = "var(--bad)";
      fill.style.background = "var(--bad)";
      var note = document.createElement("div");
      note.className = "err";
      note.textContent = message;
      row.appendChild(note);
    }

    if (file.size > MAX_BYTES) {
      fail("Over the 100 MB limit. This one is " + fmtBytes(file.size) + ".");
      return done();
    }

    state.textContent = "0%";

    var xhr = new XMLHttpRequest();
    xhr.open("PUT", "/public/upload?filename=" + encodeURIComponent(file.name));
    xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");

    xhr.upload.addEventListener("progress", function (event) {
      if (!event.lengthComputable) return;
      var percent = Math.round((event.loaded / event.total) * 100);
      fill.style.width = percent + "%";
      state.textContent = percent + "%";
    });

    xhr.addEventListener("load", function () {
      var data = {};
      try { data = JSON.parse(xhr.responseText); } catch (error) {}

      if (xhr.status >= 200 && xhr.status < 300 && data.url) {
        row.remove();
        var entries = living(read()).filter(function (item) { return item.id !== data.id; });
        entries.unshift({
          id: data.id,
          name: data.name,
          size: data.size,
          content_type: data.content_type,
          url: data.url,
          expires_at: data.expires_at
        });
        write(entries.slice(0, 100));
        render();
        toast("Link ready");
      } else {
        fail((data.error && data.error.message) || "Upload failed. Try again.");
      }
      done();
    });

    xhr.addEventListener("error", function () {
      fail("Connection dropped before the upload finished.");
      done();
    });

    xhr.send(file);
  }

  render();

  /* ---------- sign in ---------- */

  var form = document.getElementById("login");
  var keyField = document.getElementById("key");
  var errorBox = document.getElementById("login-err");
  var label = document.getElementById("login-label");
  var submit = document.getElementById("login-btn");

  document.getElementById("reveal").addEventListener("click", function () {
    keyField.type = keyField.type === "password" ? "text" : "password";
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var token = keyField.value.trim();
    errorBox.classList.remove("on");

    if (!token) {
      errorBox.textContent = "Enter your API key to continue.";
      errorBox.classList.add("on");
      return;
    }

    submit.disabled = true;
    label.textContent = "Signing in...";

    fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ token: token })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Login failed.");
          return data;
        });
      })
      .then(function () { location.href = "/dashboard"; })
      .catch(function (error) {
        errorBox.textContent = error.message;
        errorBox.classList.add("on");
        submit.disabled = false;
        label.textContent = "Sign in";
      });
  });
})();
</script>
</body>
</html>`
  );
}


/* ============================================================
   DOCUMENTATION
   ============================================================ */

function endpointBlock({ verb, path, tag, note, blocks = [] }) {
  const helpers = "'";
  const body = blocks
    .map(
      (block) =>
        '<div class="lbl">' + block.label + "</div><pre>" + block.code + "</pre>"
    )
    .join("");

  const toneClass = { PUT: "put", POST: "post", GET: "get", DELETE: "del" }[verb] || "";

  return (
    '<div class="ep"><div class="ep-h">' +
    '<span class="v ' + toneClass + '">' + verb + "</span>" +
    '<span class="p">' + path + "</span>" +
    (tag ? '<span class="tag">' + tag + "</span>" : "") +
    "</div>" +
    '<div class="ep-b">' +
    (note ? "<p>" + note + "</p>" : "") +
    body +
    "</div></div>"
  );
}

function docsPage() {
  const code = (value) => "<code>" + value + "</code>";

  const publicSection =
    endpointBlock({
      verb: "PUT",
      path: "/public/upload",
      tag: "no auth",
      note:
        "Open upload with a " + code("100 MB") + " cap and a fixed seven-day term. " +
        code("Content-Length") +
        " is required. HTML and SVG are stored as " +
        code("application/octet-stream") +
        " and served as downloads rather than rendered. Send " +
        code("POST") +
        " with " +
        code("multipart/form-data") +
        " and a " +
        code("file") +
        " field if you prefer form uploads.",
      blocks: [
        {
          label: "Request",
          code:
            '<span class="a">curl</span> -X PUT \\' +
            '\n  <span class="s">"https://YOUR-WORKER/public/upload?filename=notes.txt"</span> \\' +
            '\n  -H <span class="n">"content-type: text/plain"</span> \\' +
            '\n  --data-binary <span class="n">"@notes.txt"</span>',
        },
        {
          label: "Response",
          code:
            "{\n" +
            '  <span class="s">"object"</span>: <span class="a">"file"</span>,\n' +
            '  <span class="s">"id"</span>: <span class="a">"abc123..."</span>,\n' +
            '  <span class="s">"expires_at"</span>: <span class="a">"..."</span>,\n' +
            '  <span class="s">"url"</span>: <span class="a">"https://YOUR-WORKER/f/abc123..."</span>\n' +
            "}",
        },
      ],
    }) +
    endpointBlock({
      verb: "GET",
      path: "/f/:id",
      tag: "no auth",
      note:
        "Serves publicly uploaded files only; private objects return " +
        code("404") +
        " here. A browser gets a viewer page, anything that does not ask for " +
        code("text/html") +
        " gets the bytes. Add " +
        code("?raw=1") +
        " for bytes from a browser or " +
        code("?download=1") +
        " to force an attachment. " +
        code("Range") +
        " requests return " +
        code("206") +
        " and expired links return " +
        code("410") +
        ".",
    });

  const statusSection =
    endpointBlock({
      verb: "GET",
      path: "/api/health",
      blocks: [
        {
          label: "Response",
          code:
            "{\n" +
            '  <span class="s">"object"</span>: <span class="a">"health"</span>,\n' +
            '  <span class="s">"status"</span>: <span class="a">"ok"</span>,\n' +
            '  <span class="s">"version"</span>: <span class="a">"' + VERSION + '"</span>,\n' +
            '  <span class="s">"bucket"</span>: <span class="a">"' + BUCKET_NAME + '"</span>\n' +
            "}",
        },
      ],
    }) +
    endpointBlock({
      verb: "GET",
      path: "/api/stats",
      blocks: [
        {
          label: "Response",
          code:
            "{\n" +
            '  <span class="s">"files"</span>: <span class="a">12</span>,\n' +
            '  <span class="s">"public_files"</span>: <span class="a">3</span>,\n' +
            '  <span class="s">"bytes"</span>: <span class="a">48192031</span>,\n' +
            '  <span class="s">"formatted_bytes"</span>: <span class="a">"45.96 MB"</span>,\n' +
            '  <span class="s">"expired"</span>: <span class="a">0</span>\n' +
            "}",
        },
      ],
    });

  const uploadSection =
    endpointBlock({
      verb: "PUT",
      path: "/api/upload",
      note:
        "Streaming upload. The body pipes straight into R2 with no size cap. This is the " +
        "endpoint where you choose the lifetime.",
      blocks: [
        {
          label: "Request",
          code:
            '<span class="a">curl</span> -X PUT \\' +
            '\n  <span class="s">"https://YOUR-WORKER/api/upload?filename=video.mp4&amp;expires=7d"</span> \\' +
            '\n  -H <span class="n">"authorization: Bearer YOUR_API_KEY"</span> \\' +
            '\n  -H <span class="n">"content-type: video/mp4"</span> \\' +
            '\n  --data-binary <span class="n">"@video.mp4"</span>',
        },
      ],
    }) +
    endpointBlock({
      verb: "POST",
      path: "/api/upload",
      note: "Multipart form upload, for browser forms and " + code("curl -F") + ".",
      blocks: [
        {
          label: "Request",
          code:
            '<span class="a">curl</span> -X POST \\' +
            '\n  <span class="s">"https://YOUR-WORKER/api/upload?expires=30d"</span> \\' +
            '\n  -H <span class="n">"authorization: Bearer YOUR_API_KEY"</span> \\' +
            '\n  -F <span class="n">"file=@document.pdf"</span>',
        },
      ],
    });

  const fileSection =
    endpointBlock({
      verb: "GET",
      path: "/api/files",
      note:
        "Query parameters: " +
        code("limit") + ", " + code("cursor") + ", " + code("search") + ", " +
        code("type") + ", " + code("sort") + " (uploaded | name | size), " +
        code("order") + " (asc | desc).",
      blocks: [
        {
          label: "Response",
          code:
            "{\n" +
            '  <span class="s">"object"</span>: <span class="a">"list"</span>,\n' +
            '  <span class="s">"data"</span>: [\n' +
            "    {\n" +
            '      <span class="s">"id"</span>: <span class="a">"abc123..."</span>,\n' +
            '      <span class="s">"name"</span>: <span class="a">"photo.jpg"</span>,\n' +
            '      <span class="s">"size"</span>: <span class="a">245821</span>,\n' +
            '      <span class="s">"visibility"</span>: <span class="a">"private"</span>\n' +
            "    }\n" +
            "  ],\n" +
            '  <span class="s">"count"</span>: <span class="a">1</span>\n' +
            "}",
        },
      ],
    }) +
    endpointBlock({
      verb: "GET",
      path: "/api/files/:id",
      note:
        "Streams inline by default. Add " + code("?download=1") + " to force an attachment. " +
        code("Range") + " requests return " + code("206") + " with a " + code("Content-Range") + " header.",
    }) +
    endpointBlock({
      verb: "DELETE",
      path: "/api/files/:id",
      blocks: [
        {
          label: "Response",
          code: '{ <span class="s">"object"</span>: <span class="a">"file"</span>, <span class="s">"deleted"</span>: <span class="a">true</span> }',
        },
      ],
    }) +
    endpointBlock({
      verb: "DELETE",
      path: "/api/files",
      note: "Bulk delete, up to 1000 IDs per call.",
      blocks: [
        {
          label: "Request",
          code:
            '<span class="a">curl</span> -X DELETE \\' +
            '\n  <span class="s">"https://YOUR-WORKER/api/files"</span> \\' +
            '\n  -H <span class="n">"authorization: Bearer YOUR_API_KEY"</span> \\' +
            '\n  -H <span class="n">"content-type: application/json"</span> \\' +
            '\n  --data <span class="n">@ids.json</span>',
        },
        {
          label: "ids.json",
          code: '{ <span class="s">"ids"</span>: [<span class="a">"abc123"</span>, <span class="a">"def456"</span>] }',
        },
      ],
    });

  const lifetimes = [
    ["1h", "1 hour", ""],
    ["6h", "6 hours", ""],
    ["12h", "12 hours", ""],
    ["1d", "1 day", ""],
    ["3d", "3 days", ""],
    ["7d", "7 days", "fixed for public uploads"],
    ["30d", "30 days", ""],
    ["90d", "90 days", ""],
    ["never", "no expiration", ""],
  ];

  const table =
    '<table class="exp"><thead><tr><th>Value</th><th>Lifetime</th><th></th></tr></thead><tbody>' +
    lifetimes
      .map(
        (row) =>
          "<tr><td>" + row[0] + "</td><td>" + row[1] + "</td><td>" +
          (row[2] ? '<span class="pill warn">' + row[2] + "</span>" : "") +
          "</td></tr>"
      )
      .join("") +
    "</tbody></table>";

  return htmlPage(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API documentation &mdash; Content Delivery</title>
<meta name="description" content="REST API reference for Content Delivery: uploads, expiration, listing, downloads, stats, and deletion.">
${HEAD}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
${SITE_HEADER}
<main id="main">
<div class="doc">
  <div class="doc-h">
    <h1>API documentation</h1>
    <p>An authenticated REST API over your Cloudflare R2 bucket, plus one open endpoint for public sharing. Streaming upload and download, per-file expiration, search, sorting and bulk deletion.</p>
    <div class="note">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/></svg>
      <div>Everything under <code>/api/</code> needs <code>authorization: Bearer YOUR_API_KEY</code>. The Worker reads the key from its <code>API_KEY</code> secret. <code>/public/upload</code> and <code>/f/:id</code> are the only open routes.</div>
    </div>
  </div>

  <div class="grp">Public &mdash; no key</div>
  ${publicSection}

  <div class="grp">Status</div>
  ${statusSection}

  <div class="grp">Uploads</div>
  ${uploadSection}

  <div class="grp">Files</div>
  ${fileSection}

  <div class="grp">Lifetime values</div>
  <p class="sec-p" style="font-size:14px;margin-top:14px">Accepted by the private API at upload. Public uploads ignore this and always get seven days.</p>
  ${table}
</div>
</main>
${SITE_FOOTER}
</body>
</html>`
  );
}


/* ============================================================
   STATUS PAGES
   ============================================================ */

function statusPage({ status, code, title, message, tone }) {
  const accent = tone === "warn" ? "var(--amber)" : "var(--bad)";

  return htmlPage(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${title} &mdash; Content Delivery</title>
${HEAD}
</head>
<body>
${SITE_HEADER}
<main id="main">
<div class="status">
  <div class="box">
    <div class="code" style="color:${accent}">${code}</div>
    <h1>${title}</h1>
    <p>${message}</p>
    <div class="a"><a class="btn pri" href="/">Back to Content Delivery</a></div>
  </div>
</div>
</main>
${SITE_FOOTER}
</body>
</html>`,
    status
  );
}

function notFoundPage() {
  return statusPage({
    status: 404,
    code: "404",
    title: "That page does not exist",
    message:
      "The link may be wrong, or the file may have been deleted. Head back and send a new one.",
  });
}

function expiredPage() {
  return statusPage({
    status: 410,
    code: "410",
    title: "This link has expired",
    message:
      "Public files are kept for seven days and then deleted. Ask whoever sent it to upload the file again.",
    tone: "warn",
  });
}

/* ============================================================
   PREVIEW PAGE
   ============================================================ */

function previewGlyph(type) {
  type = String(type || "").toLowerCase();
  if (type.startsWith("image/")) return "img";
  if (type.startsWith("video/")) return "vid";
  if (type.startsWith("audio/")) return "aud";
  if (type.includes("pdf")) return "pdf";
  if (type.includes("zip") || type.includes("compressed")) return "zip";
  if (type.includes("json") || type.startsWith("text/")) return "txt";
  return "bin";
}

const GLYPHS = {
  img: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M21 16l-5-5-6 6"/>',
  vid: '<rect x="3" y="5" width="13" height="14" rx="1.5"/><path d="M16 10l5-3v10l-5-3z"/>',
  aud: '<path d="M4 10v4M8 7v10M12 4v16M16 8v8M20 11v2"/>',
  pdf: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  zip: '<path d="M4 6h16v14H4z"/><path d="M12 6v6M10 12h4M12 15v3"/>',
  txt: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M8 13h8M8 17h5"/>',
  bin: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
};

function glyphSvg(name) {
  return (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    (GLYPHS[name] || GLYPHS.bin) +
    "</svg>"
  );
}

function previewPage(file) {
  const raw = PUBLIC_PREFIX + encodeURIComponent(file.id) + "?raw=1";
  const download = PUBLIC_PREFIX + encodeURIComponent(file.id) + "?download=1";
  const type = String(file.type || "").toLowerCase();
  const name = htmlEscape(file.name);

  let media;

  if (type.startsWith("image/")) {
    media = '<img src="' + raw + '" alt="' + name + '">';
  } else if (type.startsWith("video/")) {
    media =
      '<video src="' + raw + '" controls playsinline preload="metadata"></video>';
  } else if (type.startsWith("audio/")) {
    media = '<audio src="' + raw + '" controls preload="metadata"></audio>';
  } else if (type.includes("pdf")) {
    media = '<iframe src="' + raw + '" title="' + name + '"></iframe>';
  } else if (
    type.startsWith("text/") ||
    type.includes("json") ||
    type.includes("csv") ||
    type.includes("xml")
  ) {
    media = '<pre id="text">Loading…</pre>';
  } else {
    media =
      '<div class="nopv">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12z"/><path d="M3 3l18 18"/></svg>' +
      "<span>No preview for this file type. Download it to open.</span></div>";
  }

  return htmlPage(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${name} &mdash; Content Delivery</title>
${HEAD}
</head>
<body>
${SITE_HEADER}
<main id="main">
<div class="pv">
  <div class="pv-card">
    <div class="pv-h">
      <div class="g">${glyphSvg(previewGlyph(file.type))}</div>
      <div class="meta">
        <div class="n" title="${name}">${name}</div>
        <div class="s">${formatBytes(file.size)} &middot; ${htmlEscape(
      file.type
    )} &middot; <b>${relativeTime(file.expiresAt)}</b></div>
      </div>
      <div class="acts">
        <a class="btn pri sm" href="${download}" download>Download</a>
        <a class="btn sm" href="${raw}" target="_blank" rel="noopener">Raw</a>
      </div>
    </div>
    <div class="pv-b">${media}</div>
    <div class="pv-f">
      <input id="link" type="text" readonly aria-label="Link to this file">
      <button id="copy" class="btn" type="button"><span id="copy-label">Copy link</span></button>
    </div>
  </div>
  <p class="sec-p" style="font-size:13.5px;margin-top:18px">This link deletes itself. <a href="/" style="color:var(--amber)">Send a file of your own</a>.</p>
</div>
</main>
${SITE_FOOTER}
<script>
(function () {
  var field = document.getElementById("link");
  var copy = document.getElementById("copy");
  var label = document.getElementById("copy-label");

  field.value = location.origin + location.pathname;
  field.addEventListener("focus", function () { field.select(); });

  copy.addEventListener("click", function () {
    var mark = function () {
      label.textContent = "Copied";
      setTimeout(function () { label.textContent = "Copy link"; }, 1600);
    };
    var manual = function () {
      field.select();
      document.execCommand("copy");
      mark();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(field.value).then(mark, manual);
    } else {
      manual();
    }
  });

  var pre = document.getElementById("text");
  if (pre) {
    fetch(location.pathname + "?raw=1")
      .then(function (response) { return response.text(); })
      .then(function (body) { pre.textContent = body.slice(0, 300000); })
      .catch(function () { pre.textContent = "Could not load this file."; });
  }
})();
</script>
</body>
</html>`
  );
}


/* ============================================================
   DASHBOARD
   ============================================================ */

function dashboardShell() {
  return (
    '<header class="bar"><div class="bar-in">' +
    '<a class="mark" href="/"><i>' +
    '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M6 11l6-6 6 6"/></svg>' +
    "</i>Content Delivery</a>" +
    '<nav><a href="/docs">Docs</a><a href="/">Public drop</a></nav>' +
    '<button id="refresh" class="btn" type="button">Refresh</button>' +
    '<button id="logout" class="btn dng" type="button">Log out</button>' +
    "</div></header>"
  );
}

function dashboardPage() {
  const lifetimeOptions = [
    ["1h", "1 hour"],
    ["6h", "6 hours"],
    ["12h", "12 hours"],
    ["1d", "1 day"],
    ["3d", "3 days"],
    ["7d", "7 days"],
    ["30d", "30 days"],
    ["90d", "90 days"],
    ["never", "Never"],
  ]
    .map(
      (option) =>
        '<option value="' + option[0] + '"' +
        (option[0] === "7d" ? " selected" : "") +
        ">" + option[1] + "</option>"
    )
    .join("");

  return htmlPage(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard &mdash; Content Delivery</title>
<meta name="description" content="Manage files in your Content Delivery bucket.">
${HEAD}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
${dashboardShell()}
<main id="main">
<div class="dash">

  <div class="stats">
    <div class="stat"><div class="k">Files</div><div class="v" id="stat-files">&mdash;</div></div>
    <div class="stat"><div class="k">Storage used</div><div class="v" id="stat-storage">&mdash;</div></div>
    <div class="stat"><div class="k">Public</div><div class="v" id="stat-public">&mdash;</div></div>
    <div class="stat am"><div class="k">Expired</div><div class="v" id="stat-expired">&mdash;</div></div>
  </div>

  <section class="up" aria-label="Upload">
    <div class="top">
      <div class="h">Private upload &middot; streams to R2, no size cap</div>
      <div class="h" style="color:var(--mute)">bucket: ${BUCKET_NAME} &middot; v${VERSION}</div>
    </div>
    <div class="row">
      <input id="file-input" type="file" aria-label="Choose a file">
      <label class="sr-only" for="lifetime">Lifetime</label>
      <select id="lifetime" aria-label="Lifetime">${lifetimeOptions}</select>
      <button id="upload-button" class="btn pri" type="button">Upload</button>
    </div>
    <div id="progress" role="status"></div>
  </section>

  <section class="files" aria-label="Files">
    <div class="files-h">
      <div class="t">Files <em id="result-count">&mdash;</em></div>
    </div>

    <div class="bulkbar" id="bulk">
      <span class="n" id="selected-text">0 selected</span>
      <div style="display:flex;gap:6px">
        <button id="clear-selection" class="btn sm" type="button">Clear</button>
        <button id="bulk-delete" class="btn sm dng" type="button">Delete selected</button>
      </div>
    </div>

    <div class="filters">
      <input id="search" type="search" placeholder="Search by filename" aria-label="Search files">
      <select id="type-filter" aria-label="Filter by type">
        <option value="">All types</option>
        <option value="image/">Images</option>
        <option value="video/">Videos</option>
        <option value="audio/">Audio</option>
        <option value="application/pdf">PDF</option>
        <option value="text/">Text</option>
        <option value="application/zip">ZIP</option>
      </select>
      <select id="sort" aria-label="Sort by">
        <option value="uploaded">Newest first</option>
        <option value="name">Name</option>
        <option value="size">Size</option>
      </select>
    </div>

    <div class="tablewrap">
      <table class="files-t">
        <thead>
          <tr>
            <th class="cb"><input id="select-all" type="checkbox" aria-label="Select all"></th>
            <th>File</th>
            <th>Size</th>
            <th>Uploaded</th>
            <th>Expires</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </section>

</div>
</main>
<div class="toast" id="toast" role="status"></div>
<div class="modal" id="modal" role="dialog" aria-modal="true" aria-label="File information">
  <div class="card">
    <div class="mh">
      <span>File information</span>
      <button id="modal-close" class="ib" type="button" aria-label="Close">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>
      </button>
    </div>
    <div id="modal-body" class="kv"></div>
  </div>
</div>
<script>(function () {
  var files = [];
  var selected = {};
  var timer = null;

  var GLYPH = {
    img: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M21 16l-5-5-6 6"/>',
    vid: '<rect x="3" y="5" width="13" height="14" rx="1.5"/><path d="M16 10l5-3v10l-5-3z"/>',
    aud: '<path d="M4 10v4M8 7v10M12 4v16M16 8v8M20 11v2"/>',
    pdf: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    zip: '<path d="M4 6h16v14H4z"/><path d="M12 6v6M10 12h4M12 15v3"/>',
    txt: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M8 13h8M8 17h5"/>',
    bin: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
  };

  function glyph(type) {
    type = String(type || "").toLowerCase();
    if (type.indexOf("image/") === 0) return "img";
    if (type.indexOf("video/") === 0) return "vid";
    if (type.indexOf("audio/") === 0) return "aud";
    if (type.indexOf("pdf") > -1) return "pdf";
    if (type.indexOf("zip") > -1 || type.indexOf("compressed") > -1) return "zip";
    if (type.indexOf("json") > -1 || type.indexOf("text/") === 0) return "txt";
    return "bin";
  }

  function glyphSvg(type) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + GLYPH[glyph(type)] + "</svg>";
  }

  function esc(value) {
    var node = document.createElement("div");
    node.textContent = String(value == null ? "" : value);
    return node.innerHTML;
  }

  function fmtBytes(bytes) {
    bytes = Number(bytes) || 0;
    if (!bytes) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB", "PB"];
    var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }

  function fmtDate(value) {
    var d = new Date(value);
    if (isNaN(d)) return "—";
    return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  }

  function relative(value) {
    var diff = new Date(value).getTime() - Date.now();
    if (diff <= 0) return "expired";
    var minutes = Math.floor(diff / 60000);
    if (minutes < 60) return "in " + Math.max(1, minutes) + "m";
    var hours = Math.floor(minutes / 60);
    if (hours < 24) return "in " + hours + "h";
    return "in " + Math.floor(hours / 24) + "d";
  }

  function ids() {
    return Object.keys(selected);
  }

  function toast(message, bad) {
    var node = document.getElementById("toast");
    node.textContent = message;
    node.className = "toast on" + (bad ? " bad" : "");
    clearTimeout(window.__toast);
    window.__toast = setTimeout(function () { node.className = "toast"; }, 3200);
  }

  function api(path, options) {
    return fetch(path, Object.assign({ credentials: "same-origin" }, options || {})).then(
      function (response) {
        if (response.status === 401) {
          location.href = "/";
          throw new Error("Session expired.");
        }
        return response;
      }
    );
  }

  function refreshAll() {
    return Promise.all([loadFiles(), loadStats()]);
  }

  function skeleton() {
    var rows = "";
    for (var i = 0; i < 5; i++) {
      rows += '<tr><td class="cb"></td>' +
        '<td><div style="height:13px;width:180px;background:var(--glass-3)"></div></td>' +
        '<td><div style="height:13px;width:52px;background:var(--glass-3)"></div></td>' +
        '<td><div style="height:13px;width:110px;background:var(--glass-3)"></div></td>' +
        '<td><div style="height:13px;width:56px;background:var(--glass-3)"></div></td>' +
        '<td><div style="height:13px;width:200px;background:var(--glass-3)"></div></td></tr>';
    }
    return rows;
  }

  function emptyRow(title, text) {
    return '<tr><td colspan="6"><div class="empty">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M4 8l8-4 8 4v8l-8 4-8-4z"/><path d="M4 8l8 4 8-4M12 12v8"/></svg>' +
      "<b>" + title + "</b><p>" + text + "</p></div></td></tr>";
  }

  function loadFiles() {
    var body = document.getElementById("rows");
    body.innerHTML = skeleton();

    var params = new URLSearchParams({
      limit: "1000",
      sort: document.getElementById("sort").value,
      order: "desc"
    });

    var search = document.getElementById("search").value.trim();
    var type = document.getElementById("type-filter").value;
    if (search) params.set("search", search);
    if (type) params.set("type", type);

    return api("/api/files?" + params)
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Could not load files.");
          return data;
        });
      })
      .then(function (data) {
        files = data.data || [];
        renderFiles();
      })
      .catch(function (error) {
        body.innerHTML = emptyRow("Could not load files", esc(error.message));
      });
  }

  function renderFiles() {
    var body = document.getElementById("rows");
    document.getElementById("result-count").textContent =
      files.length + (files.length === 1 ? " file" : " files");

    if (!files.length) {
      body.innerHTML = emptyRow("Nothing here yet", "Upload your first file above and it shows up in this list.");
      updateBulk();
      return;
    }

    body.innerHTML = "";

    files.forEach(function (file) {
      var tr = document.createElement("tr");

      var expiry;
      if (!file.expires_at) {
        expiry = '<span class="pill never">never</span>';
      } else if (Date.parse(file.expires_at) <= Date.now()) {
        expiry = '<span class="pill dead">expired</span>';
      } else {
        expiry = '<span class="pill warn">' + relative(file.expires_at) + "</span>";
      }

      var badge = file.visibility === "public" ? '<span class="badge">public</span>' : "";

      tr.innerHTML =
        '<td class="cb"><input type="checkbox" data-select="' + esc(file.id) + '" ' +
        (selected[file.id] ? "checked" : "") + ' aria-label="Select file"></td>' +
        '<td><div class="fn"><div class="g">' + glyphSvg(file.content_type) + "</div>" +
        '<div class="meta"><div class="n" title="' + esc(file.name) + '">' + esc(file.name) + "</div>" +
        '<div class="ct">' + esc(file.content_type) + badge + "</div></div></div></td>" +
        '<td style="font-family:var(--m);font-size:12px;white-space:nowrap">' + fmtBytes(file.size) + "</td>" +
        '<td style="font-family:var(--m);font-size:12px;white-space:nowrap">' + fmtDate(file.uploaded_at) + "</td>" +
        '<td>' + expiry + "</td>" +
        '<td><div class="rowact">' +
        '<button class="mini" data-open="' + esc(file.id) + '">Open</button>' +
        '<button class="mini" data-download="' + esc(file.id) + '">Download</button>' +
        (file.public_url ? '<button class="mini" data-copy="' + esc(file.id) + '">Copy link</button>' : "") +
        '<button class="mini" data-info="' + esc(file.id) + '">Info</button>' +
        '<button class="mini dng" data-delete="' + esc(file.id) + '">Delete</button>' +
        "</div></td>";

      body.appendChild(tr);
    });

    updateBulk();
  }

  function loadStats() {
    return api("/api/stats")
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (!data) return;
        document.getElementById("stat-files").textContent = data.files;
        document.getElementById("stat-storage").textContent = data.formatted_bytes;
        document.getElementById("stat-public").textContent = data.public_files || 0;
        document.getElementById("stat-expired").textContent = data.expired;
      })
      .catch(function () {});
  }
  /* ---------- upload ---------- */

  function upload() {
    var input = document.getElementById("file-input");
    var file = input.files[0];

    if (!file) {
      toast("Choose a file first.", true);
      return;
    }

    var progress = document.getElementById("progress");
    var button = document.getElementById("upload-button");
    var lifetime = document.getElementById("lifetime").value;

    button.disabled = true;
    progress.textContent = "uploading " + file.name + " (" + lifetime + ")…";

    var url = "/api/upload?" + new URLSearchParams({ filename: file.name, expires: lifetime });

    api(url, {
      method: "PUT",
      headers: { "Content-Type": file.type || "application/octet-stream" },
      body: file
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Upload failed.");
          return data;
        });
      })
      .then(function () {
        progress.textContent = "uploaded " + file.name;
        toast("File uploaded.");
        input.value = "";
        return refreshAll();
      })
      .catch(function (error) {
        progress.textContent = "";
        toast(error.message, true);
      })
      .then(function () { button.disabled = false; });
  }

  /* ---------- row actions ---------- */

  function deleteFile(id) {
    var file = files.filter(function (item) { return item.id === id; })[0];
    if (!confirm("Delete " + ((file && file.name) || "this file") + " permanently?")) return;

    api("/api/files/" + encodeURIComponent(id), { method: "DELETE" })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Delete failed.");
          return data;
        });
      })
      .then(function () {
        delete selected[id];
        toast("File deleted.");
        return refreshAll();
      })
      .catch(function (error) { toast(error.message, true); });
  }

  function copyPublic(id) {
    var file = files.filter(function (item) { return item.id === id; })[0];
    if (!file || !file.public_url) return;

    var url = location.origin + file.public_url;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(
        function () { toast("Link copied."); },
        function () { window.prompt("Copy this link", url); }
      );
    } else {
      window.prompt("Copy this link", url);
    }
  }

  /* ---------- bulk ---------- */

  function updateBulk() {
    var bar = document.getElementById("bulk");
    var count = ids().length;
    document.getElementById("selected-text").textContent = count + " selected";
    bar.classList.toggle("on", count > 0);
  }

  function bulkDelete() {
    var list = ids();
    if (!list.length) return;
    if (!confirm("Delete " + list.length + " selected files?")) return;

    api("/api/files", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: list })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Bulk delete failed.");
          return data;
        });
      })
      .then(function (data) {
        selected = {};
        toast(data.deleted + " files deleted.");
        return refreshAll();
      })
      .catch(function (error) { toast(error.message, true); });
  }

  /* ---------- info modal ---------- */

  function cell(label, value, wide) {
    return '<div' + (wide ? ' class="wide"' : "") + '>' +
      '<div class="k">' + label + "</div>" +
      '<div class="v">' + value + "</div></div>";
  }

  function showInfo(id) {
    var file = files.filter(function (item) { return item.id === id; })[0];
    if (!file) return;

    document.getElementById("modal-body").innerHTML =
      cell("Name", esc(file.name)) +
      cell("Size", fmtBytes(file.size)) +
      cell("Content type", esc(file.content_type)) +
      cell("Visibility", esc(file.visibility || "private")) +
      cell("Uploaded", fmtDate(file.uploaded_at)) +
      cell("Expires", file.expires_at ? fmtDate(file.expires_at) : "Never") +
      cell("ID", esc(file.id), true) +
      cell("ETag", esc(file.etag || "—"), true) +
      cell("API URL", esc(location.origin + "/api/files/" + file.id), true) +
      (file.public_url ? cell("Public link", esc(location.origin + file.public_url), true) : "");

    document.getElementById("modal").classList.add("on");
  }

  function closeModal() {
    document.getElementById("modal").classList.remove("on");
  }

  /* ---------- wiring ---------- */

  document.getElementById("rows").addEventListener("click", function (event) {
    var button = event.target.closest("button");
    if (!button) return;
    var id;
    if ((id = button.getAttribute("data-open"))) window.open("/api/files/" + encodeURIComponent(id), "_blank");
    else if ((id = button.getAttribute("data-download"))) window.open("/api/files/" + encodeURIComponent(id) + "?download=1", "_blank");
    else if ((id = button.getAttribute("data-copy"))) copyPublic(id);
    else if ((id = button.getAttribute("data-info"))) showInfo(id);
    else if ((id = button.getAttribute("data-delete"))) deleteFile(id);
  });

  document.getElementById("rows").addEventListener("change", function (event) {
    var id = event.target.getAttribute("data-select");
    if (!id) return;
    if (event.target.checked) selected[id] = true;
    else delete selected[id];
    updateBulk();
  });

  document.getElementById("select-all").addEventListener("change", function () {
    if (this.checked) files.forEach(function (file) { selected[file.id] = true; });
    else selected = {};
    renderFiles();
  });

  document.getElementById("clear-selection").addEventListener("click", function () {
    selected = {};
    document.getElementById("select-all").checked = false;
    renderFiles();
  });

  document.getElementById("bulk-delete").addEventListener("click", bulkDelete);
  document.getElementById("upload-button").addEventListener("click", upload);
  document.getElementById("refresh").addEventListener("click", function () { refreshAll(); });
  document.getElementById("sort").addEventListener("change", loadFiles);
  document.getElementById("type-filter").addEventListener("change", loadFiles);

  document.getElementById("search").addEventListener("input", function () {
    clearTimeout(timer);
    timer = setTimeout(loadFiles, 250);
  });

  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal").addEventListener("click", function (event) {
    if (event.target.id === "modal") closeModal();
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeModal();
  });

  document.getElementById("logout").addEventListener("click", function () {
    fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).finally(function () {
      location.href = "/";
    });
  });

  /* drop a file onto the input by dragging anywhere on the upload panel */
  (function () {
    var panel = document.querySelector(".up");
    var input = document.getElementById("file-input");
    ["dragenter", "dragover"].forEach(function (name) {
      panel.addEventListener(name, function (event) {
        event.preventDefault();
        panel.style.borderColor = "var(--amber)";
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      panel.addEventListener(name, function (event) {
        event.preventDefault();
        panel.style.borderColor = "";
        if (name === "drop" && event.dataTransfer.files.length) input.files = event.dataTransfer.files;
      });
    });
  })();

  refreshAll();
})();
</script>
</body>
</html>`
  );
}

