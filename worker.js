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

  const diff = timestamp - Date.now();
  if (diff <= 0) return "expired";

  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return `expires in ${Math.max(1, Math.floor(diff / 60000))} minutes`;
  if (hours < 48) return `expires in ${hours} hours`;
  return `expires in ${Math.floor(hours / 24)} days`;
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
   SHARED HEAD / DESIGN TOKENS
   ============================================================ */

const FAVICON = `<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23070b12'/%3E%3Cpath d='M9 21a5 5 0 0 1 .9-9.9A6.5 6.5 0 0 1 22.5 13 4.5 4.5 0 0 1 22 21.5H9z' fill='none' stroke='%23f38020' stroke-width='2' stroke-linejoin='round'/%3E%3C/svg%3E">`;

const TAILWIND_CONFIG = `tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "primary": "#f38020",
        "primary-container": "#ea580c",
        "primary-fixed": "#fdba74",
        "primary-fixed-dim": "#fb923c",
        "inverse-primary": "#c2410c",
        "secondary": "#38bdf8",
        "tertiary": "#38bdf8",
        "tertiary-fixed": "#7dd3fc",
        "background": "#070b12",
        "surface": "#070b12",
        "surface-deep": "#070b12",
        "surface-base": "#0a0f1d",
        "surface-card": "#0d1527",
        "surface-raised": "#131e33",
        "surface-container": "#0f172a",
        "surface-container-high": "#17233c",
        "surface-variant": "#1e293b",
        "border-subtle": "#152033",
        "border-highlight": "#1e2d4a",
        "outline": "#475569",
        "text-primary": "#f8fafc",
        "text-secondary": "#94a3b8",
        "text-muted": "#64748b",
        "on-surface": "#f1f5f9",
        "on-surface-variant": "#94a3b8",
        "on-primary": "#ffffff",
        "error": "#ffb4ab",
        "method-get": "#38bdf8",
        "method-post": "#fbbf24",
        "method-put": "#f38020",
        "method-delete": "#f87171",
        "accent-glow": "rgba(243, 128, 32, 0.16)"
      },
      borderRadius: { DEFAULT: "0.25rem", lg: "0.5rem", xl: "0.75rem", full: "9999px" },
      spacing: {
        "space-2xs": "0.25rem",
        "space-xs": "0.5rem",
        "space-sm": "0.75rem",
        "space-md": "1rem",
        "space-lg": "1.5rem",
        "space-xl": "2rem",
        "space-2xl": "3rem",
        "space-3xl": "4.5rem",
        "space-4xl": "6rem",
        "gutter-mobile": "1rem",
        "gutter-desktop": "1.5rem",
        "container-max": "1140px"
      },
      fontFamily: {
        "display-hero": ["Outfit"],
        "headline-lg": ["Outfit"],
        "headline-md": ["Outfit"],
        "headline-sm": ["Outfit"],
        "body-lg": ["Outfit"],
        "body-md": ["Outfit"],
        "body-sm": ["Outfit"],
        "caption": ["Outfit"],
        "eyebrow": ["JetBrains Mono"],
        "label-code-md": ["JetBrains Mono"],
        "label-code-lg": ["JetBrains Mono"]
      },
      fontSize: {
        "display-hero": ["56px", { lineHeight: "64px", letterSpacing: "-0.03em", fontWeight: "700" }],
        "headline-lg": ["36px", { lineHeight: "44px", letterSpacing: "-0.02em", fontWeight: "600" }],
        "headline-md": ["24px", { lineHeight: "32px", letterSpacing: "-0.01em", fontWeight: "600" }],
        "headline-sm": ["18px", { lineHeight: "26px", letterSpacing: "-0.005em", fontWeight: "600" }],
        "body-lg": ["16px", { lineHeight: "26px", fontWeight: "400" }],
        "body-md": ["14px", { lineHeight: "22px", fontWeight: "400" }],
        "body-sm": ["13px", { lineHeight: "18px", fontWeight: "400" }],
        "caption": ["12px", { lineHeight: "16px", fontWeight: "400" }],
        "eyebrow": ["11px", { lineHeight: "16px", letterSpacing: "0.12em", fontWeight: "600" }],
        "label-code-md": ["12px", { lineHeight: "18px", fontWeight: "500" }],
        "label-code-lg": ["14px", { lineHeight: "20px", letterSpacing: "-0.01em", fontWeight: "500" }]
      }
    }
  }
};`;

const BASE_STYLE = `@layer base {
  html, body { margin: 0; padding: 0; }
  body { overscroll-behavior-y: none; }
}

::selection { background: #f38020; color: #fff; }

:focus-visible { outline: 2px solid #f38020; outline-offset: 2px; border-radius: 4px; }

.skip {
  position: absolute;
  left: -9999px;
  top: 0;
  z-index: 100;
  padding: 10px 16px;
  background: #f38020;
  color: #fff;
  font-weight: 600;
  border-radius: 0 0 8px 0;
}

.skip:focus { left: 0; }

.material-symbols-outlined {
  font-variation-settings: "FILL" 0, "wght" 400, "GRAD" 0, "opsz" 24;
  user-select: none;
}

@keyframes rise {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.rise { animation: rise .35s cubic-bezier(.22,.8,.3,1) both; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    transition-duration: .01ms !important;
  }
}`;

const HEAD_ASSETS = `<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0&display=swap" rel="stylesheet">
${FAVICON}
<script src="https://cdn.tailwindcss.com?plugins=forms"></script>
<script>${TAILWIND_CONFIG}</script>
<style>${BASE_STYLE}</style>`;

const SITE_HEADER = `<header class="fixed top-0 left-0 right-0 z-50 bg-surface-deep/85 backdrop-blur-xl border-b border-border-subtle">
  <div class="h-16 max-w-[1140px] mx-auto px-gutter-mobile lg:px-gutter-desktop flex items-center justify-between">
    <a class="flex items-center gap-space-xs transition-opacity hover:opacity-90" href="/">
      <div class="w-8 h-8 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center">
        <span class="material-symbols-outlined text-primary text-[18px]">cloud_sync</span>
      </div>
      <span class="font-headline-sm text-headline-sm text-text-primary tracking-tight">Content Delivery</span>
    </a>

    <nav class="hidden md:flex items-center gap-space-xl">
      <a class="font-body-md text-body-md text-on-surface-variant hover:text-on-surface transition-colors" href="/#share">Share a file</a>
      <a class="font-body-md text-body-md text-on-surface-variant hover:text-on-surface transition-colors" href="/#features">Features</a>
      <a class="font-body-md text-body-md text-on-surface-variant hover:text-on-surface transition-colors" href="/#api">API</a>
      <a class="font-body-md text-body-md text-on-surface-variant hover:text-on-surface transition-colors" href="/docs">Docs</a>
    </nav>

    <div class="flex items-center gap-space-md">
      <a class="px-space-md py-space-xs rounded-lg bg-primary text-white font-headline-sm text-body-sm hover:bg-primary-container transition-all shadow-md shadow-primary/20" href="/dashboard">Dashboard</a>
    </div>
  </div>
</header>`;

const SITE_FOOTER = `<footer class="w-full bg-surface-base border-t border-border-subtle py-space-xl mt-space-3xl">
  <div class="max-w-[1140px] mx-auto px-gutter-mobile lg:px-gutter-desktop flex flex-col sm:flex-row items-center justify-between gap-space-md text-center sm:text-left">
    <div class="flex items-center gap-space-xs text-text-muted font-body-sm text-body-sm">
      <span class="material-symbols-outlined text-[16px] text-primary">bolt</span>
      <span>Content Delivery — Cloudflare Workers + R2</span>
    </div>
    <div class="flex items-center gap-space-lg">
      <a class="font-body-sm text-body-sm text-on-surface-variant hover:text-on-surface transition-colors" href="/docs">Documentation</a>
      <a class="font-body-sm text-body-sm text-on-surface-variant hover:text-on-surface transition-colors" href="/dashboard">Dashboard</a>
    </div>
  </div>
</footer>`;

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
   PUBLIC WEBSITE
   ============================================================ */

function publicPage() {
  return htmlPage(
`<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Content Delivery — share files from the edge</title>
<meta name="description" content="Drop a file, get a link. A private storage API backed by Cloudflare R2 with expiring links, streaming uploads, and a public uploader.">
${HEAD_ASSETS}
</head>
<body class="bg-surface-deep font-body-md text-body-md text-on-surface antialiased">

<a class="skip" href="#main">Skip to content</a>

${SITE_HEADER}

<main id="main" class="w-full pt-16 bg-surface-deep">
<div class="relative w-full overflow-hidden">

<div class="absolute -top-40 left-1/2 -translate-x-1/2 w-[720px] h-[360px] bg-primary/15 blur-[130px] pointer-events-none rounded-full"></div>
<div class="absolute top-96 -left-32 w-80 h-80 bg-tertiary/10 blur-[100px] pointer-events-none rounded-full"></div>

<!-- SECTION 1: PUBLIC UPLOAD -->
<section id="share" class="max-w-[1140px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop pt-space-2xl pb-space-3xl relative">
  <div class="flex flex-col items-start max-w-2xl mb-space-xl">
    <div class="inline-flex items-center gap-space-xs px-space-sm py-1 rounded-full bg-surface-raised border border-border-subtle mb-space-sm">
      <span class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>
      <span class="font-eyebrow text-eyebrow uppercase text-primary tracking-widest">Public upload</span>
    </div>

    <h1 class="font-display-hero text-headline-lg lg:text-display-hero text-text-primary tracking-tight mb-space-xs font-bold">
      Drop a file, get a link
    </h1>

    <p class="font-body-lg text-body-lg text-text-secondary leading-relaxed">
      No key needed for this one. Files land on Cloudflare R2 and get a link anyone can
      open in the browser. Everything here deletes itself after seven days.
    </p>
  </div>

  <div class="relative rounded-2xl bg-surface-card border border-border-subtle p-space-sm sm:p-space-lg shadow-2xl transition-all duration-300 hover:border-border-highlight group">
    <div class="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-primary/40 to-transparent"></div>

    <div id="drop-target" tabindex="0" role="button" aria-label="Choose files to upload"
      class="relative flex flex-col items-center justify-center p-space-xl sm:p-space-3xl rounded-xl border-2 border-dashed border-border-subtle bg-surface-deep/90 hover:border-primary/60 hover:bg-primary/5 transition-all duration-200 cursor-pointer text-center">

      <input id="file-input" type="file" multiple class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" aria-label="Choose files">

      <div class="w-14 h-14 rounded-2xl bg-surface-raised border border-border-highlight flex items-center justify-center mb-space-md group-hover:scale-105 transition-transform duration-200 shadow-inner">
        <span class="material-symbols-outlined text-primary text-[28px]">upload_file</span>
      </div>

      <p class="font-headline-sm text-headline-sm text-text-primary mb-1">Drop files here</p>
      <p class="font-body-md text-body-md text-text-secondary mb-space-lg">
        or <span class="text-primary font-medium underline underline-offset-4 decoration-primary/40 group-hover:decoration-primary">browse</span> — you can paste from the clipboard too
      </p>

      <div class="flex flex-wrap items-center justify-center gap-y-2 gap-x-space-md text-text-muted font-body-sm text-body-sm pt-space-md border-t border-border-subtle/70 w-full max-w-lg">
        <span class="inline-flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-text-muted/60"></span>Link expires in 7 days</span>
        <span class="inline-flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-text-muted/60"></span>100 MB per file</span>
        <span class="inline-flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-text-muted/60"></span>Anyone with the link can view or download</span>
      </div>
    </div>

    <div id="queue" class="mt-space-sm space-y-space-xs" aria-live="polite"></div>

    <div id="links-panel" class="hidden">
      <div class="mt-space-lg pt-space-lg border-t border-border-subtle/80 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-space-sm">
          <span class="font-headline-sm text-body-md font-semibold text-text-primary">Your links</span>
          <span class="font-body-sm text-body-sm text-text-muted">Kept in this browser only. Expired ones disappear on their own.</span>
        </div>
        <button id="clear-links-btn" type="button" class="self-start md:self-auto px-space-sm py-1 rounded text-body-sm font-body-sm text-text-muted hover:text-method-delete transition-colors flex items-center gap-1">
          <span class="material-symbols-outlined text-[16px]">delete_sweep</span>
          Clear all
        </button>
      </div>

      <div id="links" class="mt-space-sm space-y-space-xs"></div>
    </div>
  </div>
</section>

<!-- SECTION 2: PRIVATE STORAGE + LOGIN -->
<section class="max-w-[1140px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop py-space-2xl relative">
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-xl items-start">

    <div class="lg:col-span-7 flex flex-col items-start">
      <div class="flex items-center gap-2 mb-space-sm">
        <span class="h-[1px] w-5 bg-primary"></span>
        <span class="font-eyebrow text-eyebrow uppercase text-primary tracking-wider">Private R2 storage</span>
      </div>

      <h2 class="font-display-hero text-headline-lg lg:text-display-hero text-text-primary leading-[1.08] tracking-tight font-bold mb-space-md">
        Upload once.<br>
        <span class="text-transparent bg-clip-text bg-gradient-to-r from-primary via-primary-fixed-dim to-tertiary">Deliver from the edge.</span>
      </h2>

      <p class="font-body-lg text-body-lg text-text-secondary max-w-xl mb-space-xl leading-relaxed">
        A private file API backed by Cloudflare R2. Push any file, pick an expiration, and get
        a URL back — stream it, share it, or manage everything from the dashboard.
      </p>

      <div class="flex flex-wrap items-center gap-space-sm mb-space-2xl">
        <a class="px-space-lg py-space-sm rounded-lg bg-primary text-white font-headline-sm text-body-md hover:bg-primary-container transition-all inline-flex items-center gap-space-xs shadow-lg shadow-primary/20 hover:shadow-primary/30" href="#share">
          <span>Share a file</span>
          <span class="material-symbols-outlined text-[18px]">arrow_upward</span>
        </a>
        <a class="px-space-lg py-space-sm rounded-lg bg-surface-card border border-border-subtle text-text-primary font-headline-sm text-body-md hover:border-border-highlight hover:bg-surface-raised transition-all" href="/dashboard">Open dashboard</a>
        <a class="px-space-md py-space-sm text-text-secondary hover:text-text-primary font-body-md text-body-md transition-colors flex items-center gap-1" href="/docs">
          <span>API documentation</span>
          <span class="material-symbols-outlined text-[16px]">arrow_forward</span>
        </a>
      </div>

      <div class="grid grid-cols-3 gap-space-md sm:gap-space-lg w-full max-w-lg pt-space-lg border-t border-border-subtle">
        <div>
          <div class="font-label-code-lg text-headline-md text-primary font-bold">PUT</div>
          <div class="font-body-sm text-caption text-text-muted mt-0.5">single-call upload</div>
        </div>
        <div>
          <div class="font-label-code-lg text-headline-md text-text-primary font-bold">1h – ∞</div>
          <div class="font-body-sm text-caption text-text-muted mt-0.5">per-file expiration</div>
        </div>
        <div>
          <div class="font-label-code-lg text-headline-md text-tertiary font-bold">206</div>
          <div class="font-body-sm text-caption text-text-muted mt-0.5">range streaming</div>
        </div>
      </div>
    </div>

    <div class="lg:col-span-5 w-full">
      <div class="rounded-2xl bg-surface-card border border-border-subtle p-space-lg lg:p-space-xl relative shadow-2xl">
        <div class="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-primary/30 to-transparent"></div>

        <div class="flex items-center gap-space-sm mb-space-sm">
          <div class="w-9 h-9 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary">
            <span class="material-symbols-outlined text-[20px]">lock</span>
          </div>
          <div>
            <h3 class="font-headline-md text-headline-sm text-text-primary font-semibold">Dashboard login</h3>
            <p class="font-body-sm text-caption text-text-muted">Authenticate with your API key</p>
          </div>
        </div>

        <form id="login-form" class="mt-space-lg space-y-space-md" novalidate>
          <div class="space-y-space-xs">
            <label class="block font-label-code-md text-caption text-text-secondary uppercase tracking-wider" for="api-key-input">API key</label>
            <div class="relative">
              <input id="api-key-input" type="password" autocomplete="current-password" placeholder="Paste your API key"
                class="w-full h-11 px-space-md pr-10 rounded-lg bg-surface-deep border border-border-subtle text-text-primary font-label-code-md text-body-sm placeholder:text-text-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
              <button id="reveal-key" type="button" aria-label="Show or hide the key"
                class="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors">
                <span class="material-symbols-outlined text-[18px]">visibility</span>
              </button>
            </div>
          </div>

          <div id="login-error" class="hidden rounded-lg border border-method-delete/40 bg-method-delete/10 px-space-md py-space-xs font-body-sm text-body-sm text-method-delete" role="alert"></div>

          <button id="login-button" type="submit"
            class="w-full h-11 rounded-lg bg-primary text-white font-headline-sm text-body-md font-semibold hover:bg-primary-container transition-all flex items-center justify-center gap-2 shadow-lg shadow-primary/20 disabled:opacity-60">
            <span id="login-label">Sign in</span>
            <span class="material-symbols-outlined text-[18px]">login</span>
          </button>
        </form>

        <div class="mt-space-md pt-space-md border-t border-border-subtle flex items-center justify-between text-caption text-text-muted font-label-code-md">
          <span class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-method-put"></span>
            CF Workers R2 · TLS 1.3
          </span>
          <a class="text-text-secondary hover:text-primary transition-colors" href="/docs">Read the docs</a>
        </div>
      </div>
    </div>

  </div>
</section>

<!-- SECTION 3: FEATURES -->
<section id="features" class="max-w-[1140px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop py-space-3xl relative">
  <div class="flex flex-col items-start max-w-2xl mb-space-2xl">
    <div class="flex items-center gap-2 mb-space-xs">
      <span class="h-[1px] w-5 bg-primary"></span>
      <span class="font-eyebrow text-eyebrow uppercase text-primary tracking-wider">Features</span>
    </div>
    <h2 class="font-headline-lg text-headline-lg text-text-primary font-semibold tracking-tight mb-space-xs">
      Storage built around the API, not the other way round
    </h2>
    <p class="font-body-lg text-body-md sm:text-body-lg text-text-secondary leading-relaxed">
      Private by default. The Worker holds the only key, R2 holds the bytes, and every
      operation is one HTTP call.
    </p>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-space-md">

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">air</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">Streaming end to end</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          Request bodies pipe straight into R2 with no buffering and no size cap. Downloads
          support HTTP range requests for seeking and resuming.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-method-get">
        <span>RFC 7233 · byte ranges</span>
      </div>
    </div>

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">schedule</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">Per-file expiration</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          One hour to ninety days, or never. A scheduled sweep removes expired objects
          automatically.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-primary">
        <span>Cron-driven cleanup</span>
      </div>
    </div>

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">ios_share</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">Public sharing</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          The uploader above needs no key. Those files get a seven-day link under /f/ with a
          browser preview page, and never mix with your private ones.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-method-post">
        <span>Read-gated by metadata</span>
      </div>
    </div>

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">manage_search</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">Search and sorting</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          Filter by filename or MIME type, sort by name, size, or upload time — all
          server-side.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-text-muted">
        <span>Cursor pagination</span>
      </div>
    </div>

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">dataset</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">Bulk management</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          Select any set of files and remove them in a single API call, up to a thousand at a
          time.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-method-delete">
        <span>Batch delete · 1,000 max</span>
      </div>
    </div>

    <div class="rounded-xl bg-surface-card border border-border-subtle p-space-lg flex flex-col justify-between hover:border-border-highlight hover:-translate-y-0.5 transition-all duration-200 group">
      <div>
        <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary mb-space-md group-hover:scale-105 transition-transform">
          <span class="material-symbols-outlined text-[20px]">terminal</span>
        </div>
        <h3 class="font-headline-sm text-headline-sm text-text-primary mb-space-xs font-semibold">API-first</h3>
        <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
          The dashboard is a convenience, not a requirement. Every action maps to a documented
          REST endpoint.
        </p>
      </div>
      <div class="mt-space-lg pt-space-sm border-t border-border-subtle/60 flex items-center gap-2 text-caption font-label-code-md text-tertiary">
        <span>Plain HTTP · no SDK</span>
      </div>
    </div>

  </div>
</section>

<!-- SECTION 4: QUICK START -->
<section id="api" class="max-w-[1140px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop pt-space-xl pb-space-3xl relative">
  <div class="flex flex-col items-start max-w-2xl mb-space-xl">
    <div class="flex items-center gap-2 mb-space-xs">
      <span class="h-[1px] w-5 bg-primary"></span>
      <span class="font-eyebrow text-eyebrow uppercase text-primary tracking-wider">Quick start</span>
    </div>
    <h2 class="font-headline-lg text-headline-lg text-text-primary font-semibold tracking-tight mb-space-xs">
      Simple requests, predictable responses
    </h2>
    <p class="font-body-lg text-body-md sm:text-body-lg text-text-secondary">
      Talk to R2 over plain HTTP, without an SDK in the way.
    </p>
  </div>

  <div class="rounded-2xl bg-surface-base border border-border-subtle overflow-hidden shadow-2xl">
    <div class="flex items-center justify-between border-b border-border-subtle bg-surface-deep px-space-md py-space-xs overflow-x-auto">
      <div class="flex items-center gap-space-xs">
        <button type="button" data-tab="tab-upload" class="api-tab px-space-md py-space-xs rounded-lg text-body-sm font-label-code-md flex items-center gap-space-xs transition-colors bg-surface-raised text-primary border border-border-highlight">
          <span class="px-1.5 py-0.5 rounded bg-primary/20 text-primary font-bold text-[10px]">PUT</span>
          <span>/api/upload</span>
        </button>
        <button type="button" data-tab="tab-public" class="api-tab px-space-md py-space-xs rounded-lg text-body-sm font-label-code-md flex items-center gap-space-xs transition-colors text-text-secondary hover:text-text-primary hover:bg-surface-raised border border-transparent">
          <span class="px-1.5 py-0.5 rounded bg-primary/20 text-primary font-bold text-[10px]">PUT</span>
          <span>/public/upload</span>
        </button>
        <button type="button" data-tab="tab-files" class="api-tab px-space-md py-space-xs rounded-lg text-body-sm font-label-code-md flex items-center gap-space-xs transition-colors text-text-secondary hover:text-text-primary hover:bg-surface-raised border border-transparent">
          <span class="px-1.5 py-0.5 rounded bg-tertiary/20 text-tertiary font-bold text-[10px]">GET</span>
          <span>/api/files</span>
        </button>
        <button type="button" data-tab="tab-file-id" class="api-tab px-space-md py-space-xs rounded-lg text-body-sm font-label-code-md flex items-center gap-space-xs transition-colors text-text-secondary hover:text-text-primary hover:bg-surface-raised border border-transparent">
          <span class="px-1.5 py-0.5 rounded bg-tertiary/20 text-tertiary font-bold text-[10px]">GET</span>
          <span>/f/:id</span>
        </button>
      </div>

      <button id="global-copy-btn" type="button" class="shrink-0 ml-space-md px-space-sm py-1 rounded bg-surface-raised border border-border-subtle text-text-secondary hover:text-primary transition-colors flex items-center gap-1.5 font-label-code-md text-caption">
        <span class="material-symbols-outlined text-[15px]">content_copy</span>
        <span>Copy</span>
      </button>
    </div>

    <div class="tab-pane block p-space-lg space-y-space-md" id="tab-upload">
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Request</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code><span class="text-primary">curl</span> -X PUT \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/upload?filename=photo.jpg&amp;expires=7d"</span> \\
  -H <span class="text-method-post">"Authorization: Bearer YOUR_API_KEY"</span> \\
  -H <span class="text-tertiary">"Content-Type: image/jpeg"</span> \\
  --data-binary <span class="text-text-secondary">"@photo.jpg"</span></code></pre>
      </div>
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Response</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code>{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"file"</span>,
  <span class="text-tertiary">"status"</span>: <span class="text-primary-fixed-dim">"complete"</span>,
  <span class="text-tertiary">"id"</span>: <span class="text-primary-fixed-dim">"a4e3c1…"</span>,
  <span class="text-tertiary">"name"</span>: <span class="text-primary-fixed-dim">"photo.jpg"</span>,
  <span class="text-tertiary">"download_url"</span>: <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/files/a4e3c1…"</span>
}</code></pre>
      </div>
    </div>

    <div class="tab-pane hidden p-space-lg space-y-space-md" id="tab-public">
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Request · no auth header</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code><span class="text-primary">curl</span> -X PUT \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/public/upload?filename=notes.txt"</span> \\
  -H <span class="text-tertiary">"Content-Type: text/plain"</span> \\
  --data-binary <span class="text-text-secondary">"@notes.txt"</span></code></pre>
      </div>
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Response</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code>{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"file"</span>,
  <span class="text-tertiary">"name"</span>: <span class="text-primary-fixed-dim">"notes.txt"</span>,
  <span class="text-tertiary">"expires_at"</span>: <span class="text-primary-fixed-dim">"…"</span>,
  <span class="text-tertiary">"url"</span>: <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/f/abc123…"</span>
}</code></pre>
      </div>
    </div>

    <div class="tab-pane hidden p-space-lg space-y-space-md" id="tab-files">
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Request · search and sort</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code><span class="text-tertiary">curl</span> \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/files?search=photo&amp;sort=size&amp;order=desc"</span> \\
  -H <span class="text-method-post">"Authorization: Bearer YOUR_API_KEY"</span></code></pre>
      </div>
    </div>

    <div class="tab-pane hidden p-space-lg space-y-space-md" id="tab-file-id">
      <div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">Public file · preview or raw bytes</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code><span class="text-text-secondary"># a browser gets the preview page</span>
<span class="text-primary-fixed-dim">https://cdn.pushkarsingh4343.workers.dev/f/FILE_ID</span>

<span class="text-text-secondary"># curl gets the bytes</span>
<span class="text-tertiary">curl</span> <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/f/FILE_ID"</span> -o file</code></pre>
      </div>
    </div>
  </div>
</section>

</div>
</main>

${SITE_FOOTER}

<script>
/* ---------- API tabs ---------- */

(function () {
  var tabs = document.querySelectorAll(".api-tab");
  var active = "bg-surface-raised text-primary border-border-highlight".split(" ");
  var idle = "text-text-secondary border-transparent".split(" ");

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab-pane").forEach(function (pane) {
        pane.classList.add("hidden");
        pane.classList.remove("block");
      });

      var target = document.getElementById(tab.getAttribute("data-tab"));
      if (target) {
        target.classList.remove("hidden");
        target.classList.add("block");
      }

      tabs.forEach(function (other) {
        active.forEach(function (name) { other.classList.remove(name); });
        idle.forEach(function (name) { other.classList.add(name); });
      });

      idle.forEach(function (name) { tab.classList.remove(name); });
      active.forEach(function (name) { tab.classList.add(name); });
    });
  });

  document.getElementById("global-copy-btn").addEventListener("click", function () {
    var pane = document.querySelector(".tab-pane.block");
    if (!pane) return;

    var button = this;
    var original = button.innerHTML;

    navigator.clipboard.writeText(pane.innerText.trim()).then(function () {
      button.innerHTML =
        '<span class="material-symbols-outlined text-[15px] text-primary">check</span><span class="text-primary">Copied</span>';
      setTimeout(function () { button.innerHTML = original; }, 1600);
    });
  });
})();

/* ---------- dashboard login ---------- */

(function () {
  var form = document.getElementById("login-form");
  var input = document.getElementById("api-key-input");
  var error = document.getElementById("login-error");
  var button = document.getElementById("login-button");
  var label = document.getElementById("login-label");

  document.getElementById("reveal-key").addEventListener("click", function () {
    input.type = input.type === "password" ? "text" : "password";
    this.querySelector("span").textContent =
      input.type === "password" ? "visibility" : "visibility_off";
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    var token = input.value.trim();
    error.classList.add("hidden");

    if (!token) {
      error.textContent = "Enter your API key to continue.";
      error.classList.remove("hidden");
      return;
    }

    button.disabled = true;
    label.textContent = "Signing in…";

    fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ token: token }),
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error((data.error && data.error.message) || "Login failed.");
          return data;
        });
      })
      .then(function () {
        location.href = "/dashboard";
      })
      .catch(function (err) {
        error.textContent = err.message;
        error.classList.remove("hidden");
        button.disabled = false;
        label.textContent = "Sign in";
      });
  });
})();

/* ---------- public uploader ---------- */

(function () {
  var MAX_BYTES = 100 * 1024 * 1024;
  var STORE = "cdn.links.v1";

  var target = document.getElementById("drop-target");
  var picker = document.getElementById("file-input");
  var queue = document.getElementById("queue");
  var panel = document.getElementById("links-panel");
  var box = document.getElementById("links");

  var waiting = [];
  var busy = false;

  var ROW =
    "flex items-center justify-between gap-space-sm p-space-sm rounded-lg bg-surface-deep/90 border border-border-subtle text-body-sm rise";
  var PILL =
    "w-7 h-7 rounded bg-surface-raised border border-border-subtle flex items-center justify-center text-text-secondary hover:text-primary transition-colors shrink-0";

  function esc(value) {
    var div = document.createElement("div");
    div.textContent = String(value == null ? "" : value);
    return div.innerHTML;
  }

  function size(bytes) {
    bytes = Number(bytes) || 0;
    if (!bytes) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + " " + units[i];
  }

  function glyph(type) {
    type = String(type || "").toLowerCase();
    if (type.indexOf("image/") === 0) return "image";
    if (type.indexOf("video/") === 0) return "movie";
    if (type.indexOf("audio/") === 0) return "graphic_eq";
    if (type.indexOf("pdf") > -1) return "picture_as_pdf";
    if (type.indexOf("zip") > -1 || type.indexOf("compressed") > -1) return "folder_zip";
    if (type.indexOf("json") > -1 || type.indexOf("text/") === 0) return "terminal";
    return "draft";
  }

  function remaining(iso) {
    if (!iso) return "no expiry";
    var diff = Date.parse(iso) - Date.now();
    if (diff <= 0) return "expired";

    var hours = Math.floor(diff / 3600000);
    if (hours < 1) return "expires in " + Math.max(1, Math.floor(diff / 60000)) + "m";
    if (hours < 48) return "expires in " + hours + "h";
    return "expires in " + Math.floor(hours / 24) + "d";
  }

  function read() {
    try {
      var raw = localStorage.getItem(STORE);
      var list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch (error) {
      return [];
    }
  }

  function write(list) {
    try { localStorage.setItem(STORE, JSON.stringify(list)); } catch (error) {}
  }

  function live(list) {
    var now = Date.now();
    return list.filter(function (entry) {
      if (!entry || !entry.id || !entry.url) return false;
      if (!entry.expires_at) return true;
      return Date.parse(entry.expires_at) > now;
    });
  }

  function remember(entry) {
    var list = live(read()).filter(function (item) { return item.id !== entry.id; });
    list.unshift(entry);
    if (list.length > 100) list.length = 100;
    write(list);
    render();
  }

  function forget(id) {
    write(live(read()).filter(function (item) { return item.id !== id; }));
    render();
  }

  function shortId(id) {
    return String(id || "").slice(0, 6);
  }

  function row(entry) {
    var card = document.createElement("div");
    card.className = ROW;

    card.innerHTML =
      '<div class="flex items-center gap-space-sm min-w-0">' +
        '<div class="w-8 h-8 rounded bg-surface-raised border border-border-highlight flex items-center justify-center shrink-0">' +
          '<span class="material-symbols-outlined text-primary text-[18px]">' + glyph(entry.content_type) + '</span>' +
        '</div>' +
        '<div class="min-w-0">' +
          '<p class="text-text-primary font-medium truncate">' + esc(entry.name) + '</p>' +
          '<div class="flex items-center gap-space-xs font-label-code-md text-caption text-text-muted">' +
            '<span>' + size(entry.size) + '</span><span>&bull;</span>' +
            '<span class="text-primary font-normal">' + esc(remaining(entry.expires_at)) + '</span>' +
          '</div>' +
        '</div>' +
      '</div>';

    var right = document.createElement("div");
    right.className = "flex items-center gap-space-xs shrink-0";

    var open = document.createElement("a");
    open.href = entry.url;
    open.target = "_blank";
    open.rel = "noopener";
    open.title = "Open preview";
    open.className =
      "hidden sm:flex px-space-sm py-1 rounded bg-surface-raised border border-border-subtle font-label-code-md text-caption text-method-get hover:border-primary transition-colors items-center gap-1";
    open.innerHTML =
      '<span>/f/' + esc(shortId(entry.id)) + '</span><span class="material-symbols-outlined text-[14px]">open_in_new</span>';

    var save = document.createElement("a");
    save.href = entry.url + "?download=1";
    save.setAttribute("download", entry.name || "");
    save.title = "Download file";
    save.className = PILL;
    save.innerHTML = '<span class="material-symbols-outlined text-[16px]">download</span>';

    var copy = document.createElement("button");
    copy.type = "button";
    copy.title = "Copy link";
    copy.className = PILL;
    copy.innerHTML = '<span class="material-symbols-outlined text-[16px]">content_copy</span>';
    copy.addEventListener("click", function () {
      var mark = function () {
        copy.innerHTML = '<span class="material-symbols-outlined text-[16px] text-primary">check</span>';
        setTimeout(function () {
          copy.innerHTML = '<span class="material-symbols-outlined text-[16px]">content_copy</span>';
        }, 1500);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(entry.url).then(mark, mark);
      } else {
        window.prompt("Copy this link", entry.url);
      }
    });

    var remove = document.createElement("button");
    remove.type = "button";
    remove.title = "Forget this link";
    remove.className = PILL + " hover:text-method-delete";
    remove.innerHTML = '<span class="material-symbols-outlined text-[16px]">close</span>';
    remove.addEventListener("click", function () { forget(entry.id); });

    right.appendChild(open);
    right.appendChild(save);
    right.appendChild(copy);
    right.appendChild(remove);
    card.appendChild(right);

    return card;
  }

  function render() {
    var list = live(read());
    write(list);

    if (!list.length) {
      panel.classList.add("hidden");
      box.innerHTML = "";
      return;
    }

    panel.classList.remove("hidden");
    box.innerHTML = "";
    list.forEach(function (entry) { box.appendChild(row(entry)); });
  }

  document.getElementById("clear-links-btn").addEventListener("click", function () {
    if (!confirm("Forget every saved link in this browser? The files stay online until they expire.")) return;
    write([]);
    render();
  });

  /* ---------- picking files ---------- */

  target.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      picker.click();
    }
  });

  picker.addEventListener("change", function () {
    enqueue(picker.files);
    picker.value = "";
  });

  ["dragenter", "dragover"].forEach(function (name) {
    target.addEventListener(name, function (event) {
      event.preventDefault();
      target.classList.add("border-primary", "bg-primary/5");
    });
  });

  target.addEventListener("dragleave", function (event) {
    if (!target.contains(event.relatedTarget)) {
      target.classList.remove("border-primary", "bg-primary/5");
    }
  });

  target.addEventListener("drop", function (event) {
    event.preventDefault();
    target.classList.remove("border-primary", "bg-primary/5");
    if (event.dataTransfer && event.dataTransfer.files.length) {
      enqueue(event.dataTransfer.files);
    }
  });

  document.addEventListener("paste", function (event) {
    if (!event.clipboardData || !event.clipboardData.files.length) return;
    enqueue(event.clipboardData.files);
  });

  ["dragover", "drop"].forEach(function (name) {
    window.addEventListener(name, function (event) {
      if (!target.contains(event.target)) event.preventDefault();
    });
  });

  function enqueue(list) {
    for (var i = 0; i < list.length; i++) waiting.push(list[i]);
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
    var card = document.createElement("div");
    card.className = "p-space-sm rounded-lg bg-surface-deep/90 border border-border-subtle text-body-sm rise";

    card.innerHTML =
      '<div class="flex items-center justify-between gap-space-sm">' +
        '<div class="flex items-center gap-space-sm min-w-0">' +
          '<div class="w-8 h-8 rounded bg-surface-raised border border-border-highlight flex items-center justify-center shrink-0">' +
            '<span class="material-symbols-outlined text-primary text-[18px]">' + glyph(file.type) + '</span>' +
          '</div>' +
          '<div class="min-w-0">' +
            '<p class="text-text-primary font-medium truncate">' + esc(file.name) + '</p>' +
            '<div class="font-label-code-md text-caption text-text-muted">' + size(file.size) + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="state font-label-code-md text-caption text-text-secondary shrink-0">waiting</div>' +
      '</div>' +
      '<div class="track mt-space-sm h-1 rounded-full bg-surface-raised overflow-hidden">' +
        '<i class="fill block h-full w-0 bg-primary transition-all duration-200"></i>' +
      '</div>';

    queue.insertBefore(card, queue.firstChild);

    var state = card.querySelector(".state");
    var track = card.querySelector(".track");
    var fill = card.querySelector(".fill");

    function fail(message) {
      card.classList.add("border-method-delete/40");
      track.remove();
      state.textContent = "failed";
      state.classList.remove("text-text-secondary");
      state.classList.add("text-method-delete");

      var note = document.createElement("p");
      note.className = "mt-space-xs font-body-sm text-body-sm text-method-delete";
      note.textContent = message;
      card.appendChild(note);
    }

    if (file.size > MAX_BYTES) {
      fail("Over the 100 MB limit — this one is " + size(file.size) + ".");
      done();
      return;
    }

    state.textContent = "0%";

    var xhr = new XMLHttpRequest();
    xhr.open("PUT", "/public/upload?filename=" + encodeURIComponent(file.name));
    xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");

    xhr.upload.onprogress = function (event) {
      if (!event.lengthComputable) return;
      var percent = Math.round((event.loaded / event.total) * 100);
      fill.style.width = percent + "%";
      state.textContent = percent + "%";
    };

    xhr.onload = function () {
      var data = {};
      try { data = JSON.parse(xhr.responseText); } catch (error) {}

      if (xhr.status >= 200 && xhr.status < 300 && data.url) {
        card.parentNode.removeChild(card);
        remember({
          id: data.id,
          name: data.name,
          size: data.size,
          content_type: data.content_type,
          url: data.url,
          expires_at: data.expires_at,
        });
      } else {
        fail((data.error && data.error.message) || "Upload failed. Try again.");
      }

      done();
    };

    xhr.onerror = function () {
      fail("Connection dropped before the upload finished.");
      done();
    };

    xhr.send(file);
  }

  render();
  setInterval(render, 60000);
})();
</script>

</body>
</html>`
  );
}

/* ============================================================
   DOCUMENTATION
   ============================================================ */

function methodBadge(method) {
  const tone = {
    GET: "bg-tertiary/20 text-tertiary",
    PUT: "bg-primary/20 text-primary",
    POST: "bg-method-post/20 text-method-post",
    DELETE: "bg-method-delete/20 text-method-delete",
  }[method] || "bg-surface-raised text-text-secondary";

  return `<span class="px-1.5 py-0.5 rounded ${tone} font-bold text-[10px] font-label-code-md">${method}</span>`;
}

function endpointCard({ method, path, tag = "", note = "", blocks = [] }) {
  const body = blocks
    .map(
      (block) => `<div>
        <div class="font-eyebrow text-caption text-text-muted mb-2 uppercase tracking-wider">${block.label}</div>
        <pre class="overflow-x-auto p-space-md rounded-lg bg-surface-deep border border-border-subtle font-label-code-lg text-body-sm text-text-primary leading-relaxed"><code>${block.code}</code></pre>
      </div>`
    )
    .join("\n");

  return `<div class="rounded-xl bg-surface-card border border-border-subtle overflow-hidden mb-space-md">
  <div class="flex items-center gap-space-sm px-space-lg py-space-sm border-b border-border-subtle bg-surface-base">
    ${methodBadge(method)}
    <span class="font-label-code-lg text-body-sm text-text-primary">${path}</span>
    ${
      tag
        ? `<span class="ml-auto font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">${tag}</span>`
        : ""
    }
  </div>
  <div class="p-space-lg space-y-space-md">
    ${
      note
        ? `<p class="font-body-md text-body-md text-text-secondary leading-relaxed">${note}</p>`
        : ""
    }
    ${body}
  </div>
</div>`;
}

function docsPage() {
  const code = (value) =>
    `<code class="px-1.5 py-0.5 rounded bg-surface-raised border border-border-subtle font-label-code-md text-caption text-primary">${value}</code>`;

  return htmlPage(
`<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API documentation — Content Delivery</title>
<meta name="description" content="REST API reference for Content Delivery: uploads, expiration, listing, downloads, stats, and deletion.">
${HEAD_ASSETS}
</head>
<body class="bg-surface-deep font-body-md text-body-md text-on-surface antialiased">

<a class="skip" href="#main">Skip to content</a>

${SITE_HEADER}

<main id="main" class="w-full pt-16">
<div class="relative overflow-hidden">
<div class="absolute -top-40 left-1/2 -translate-x-1/2 w-[720px] h-[300px] bg-primary/10 blur-[130px] pointer-events-none rounded-full"></div>

<div class="max-w-[900px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop pt-space-2xl pb-space-3xl relative">

  <div class="flex items-center gap-2 mb-space-sm">
    <span class="h-[1px] w-5 bg-primary"></span>
    <span class="font-eyebrow text-eyebrow uppercase text-primary tracking-wider">Reference</span>
  </div>

  <h1 class="font-display-hero text-headline-lg lg:text-display-hero text-text-primary font-bold tracking-tight mb-space-sm">
    API documentation
  </h1>

  <p class="font-body-lg text-body-lg text-text-secondary max-w-2xl leading-relaxed mb-space-lg">
    An authenticated REST API over your Cloudflare R2 bucket, plus one open endpoint for
    public sharing. Files support streaming upload and download, per-file expiration,
    search, sorting, and bulk deletion.
  </p>

  <div class="flex gap-space-sm items-start rounded-xl border border-primary/30 bg-primary/5 p-space-md mb-space-2xl">
    <span class="material-symbols-outlined text-primary text-[20px] shrink-0">key</span>
    <p class="font-body-md text-body-md text-text-secondary leading-relaxed">
      Everything under ${code("/api/")} needs ${code("Authorization: Bearer YOUR_API_KEY")}.
      The Worker reads the key from its ${code("API_KEY")} environment variable.
      ${code("/public/upload")} and ${code("/f/:id")} are the only open routes.
    </p>
  </div>

  <h2 class="font-headline-md text-headline-md text-text-primary font-semibold mb-space-md">Public</h2>

  ${endpointCard({
    method: "PUT",
    path: "/public/upload",
    tag: "no auth",
    note: `Fixed 7-day expiry and a 100 MB cap. ${code(
      "Content-Length"
    )} is required. HTML and SVG uploads are stored as ${code(
      "application/octet-stream"
    )} and served as downloads rather than rendered. Send ${code(
      "POST"
    )} with ${code("multipart/form-data")} and a ${code(
      "file"
    )} field if you prefer form uploads.`,
    blocks: [
      {
        label: "Request",
        code: `<span class="text-primary">curl</span> -X PUT \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/public/upload?filename=notes.txt"</span> \\
  -H <span class="text-tertiary">"Content-Type: text/plain"</span> \\
  --data-binary <span class="text-text-secondary">"@notes.txt"</span>`,
      },
      {
        label: "Response",
        code: `{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"file"</span>,
  <span class="text-tertiary">"id"</span>: <span class="text-primary-fixed-dim">"abc123…"</span>,
  <span class="text-tertiary">"name"</span>: <span class="text-primary-fixed-dim">"notes.txt"</span>,
  <span class="text-tertiary">"size"</span>: <span class="text-primary-fixed-dim">4821</span>,
  <span class="text-tertiary">"expires_at"</span>: <span class="text-primary-fixed-dim">"…"</span>,
  <span class="text-tertiary">"url"</span>: <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/f/abc123…"</span>
}`,
      },
    ],
  })}

  ${endpointCard({
    method: "GET",
    path: "/f/:id",
    tag: "no auth",
    note: `Serves publicly uploaded files only — private objects return ${code(
      "404"
    )} here. A browser gets a viewer page with the file rendered inline and a download
      button; anything that doesn't ask for ${code(
        "text/html"
      )}, such as curl, gets the bytes. Add ${code(
      "?raw=1"
    )} for the bytes from a browser, or ${code(
      "?download=1"
    )} to force an attachment. ${code("Range")} requests return ${code(
      "206"
    )} and expired links return ${code("410")}. Set the ${code(
      "PUBLIC_UPLOADS"
    )} variable to ${code("false")} to disable new public uploads.`,
  })}

  <h2 class="font-headline-md text-headline-md text-text-primary font-semibold mt-space-2xl mb-space-md">Status</h2>

  ${endpointCard({
    method: "GET",
    path: "/api/health",
    blocks: [
      {
        label: "Response",
        code: `{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"health"</span>,
  <span class="text-tertiary">"status"</span>: <span class="text-primary-fixed-dim">"ok"</span>,
  <span class="text-tertiary">"version"</span>: <span class="text-primary-fixed-dim">"${VERSION}"</span>,
  <span class="text-tertiary">"bucket"</span>: <span class="text-primary-fixed-dim">"${BUCKET_NAME}"</span>
}`,
      },
    ],
  })}

  ${endpointCard({
    method: "GET",
    path: "/api/stats",
    blocks: [
      {
        label: "Response",
        code: `{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"stats"</span>,
  <span class="text-tertiary">"files"</span>: <span class="text-primary-fixed-dim">12</span>,
  <span class="text-tertiary">"public_files"</span>: <span class="text-primary-fixed-dim">3</span>,
  <span class="text-tertiary">"bytes"</span>: <span class="text-primary-fixed-dim">48192031</span>,
  <span class="text-tertiary">"formatted_bytes"</span>: <span class="text-primary-fixed-dim">"45.96 MB"</span>,
  <span class="text-tertiary">"expired"</span>: <span class="text-primary-fixed-dim">0</span>
}`,
      },
    ],
  })}

  <h2 class="font-headline-md text-headline-md text-text-primary font-semibold mt-space-2xl mb-space-md">Uploads</h2>

  ${endpointCard({
    method: "PUT",
    path: "/api/upload",
    note: "Streaming upload. The body pipes directly into R2 with no size cap.",
    blocks: [
      {
        label: "Request",
        code: `<span class="text-primary">curl</span> -X PUT \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/upload?filename=video.mp4&amp;expires=7d"</span> \\
  -H <span class="text-method-post">"Authorization: Bearer YOUR_API_KEY"</span> \\
  -H <span class="text-tertiary">"Content-Type: video/mp4"</span> \\
  --data-binary <span class="text-text-secondary">"@video.mp4"</span>`,
      },
    ],
  })}

  ${endpointCard({
    method: "POST",
    path: "/api/upload",
    note: `Multipart form upload, for browser forms and ${code("curl -F")}.`,
    blocks: [
      {
        label: "Request",
        code: `<span class="text-primary">curl</span> -X POST \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/upload?expires=30d"</span> \\
  -H <span class="text-method-post">"Authorization: Bearer YOUR_API_KEY"</span> \\
  -F <span class="text-text-secondary">"file=@document.pdf"</span>`,
      },
    ],
  })}

  <h2 class="font-headline-md text-headline-md text-text-primary font-semibold mt-space-2xl mb-space-md">Files</h2>

  ${endpointCard({
    method: "GET",
    path: "/api/files",
    note: `Query parameters: ${code("limit")}, ${code("cursor")}, ${code(
      "search"
    )}, ${code("type")}, ${code("sort")} (uploaded | name | size), ${code(
      "order"
    )} (asc | desc).`,
    blocks: [
      {
        label: "Response",
        code: `{
  <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"list"</span>,
  <span class="text-tertiary">"data"</span>: [
    {
      <span class="text-tertiary">"id"</span>: <span class="text-primary-fixed-dim">"abc123…"</span>,
      <span class="text-tertiary">"name"</span>: <span class="text-primary-fixed-dim">"photo.jpg"</span>,
      <span class="text-tertiary">"size"</span>: <span class="text-primary-fixed-dim">245821</span>,
      <span class="text-tertiary">"visibility"</span>: <span class="text-primary-fixed-dim">"private"</span>,
      <span class="text-tertiary">"public_url"</span>: <span class="text-primary-fixed-dim">null</span>
    }
  ],
  <span class="text-tertiary">"count"</span>: <span class="text-primary-fixed-dim">1</span>
}`,
      },
    ],
  })}

  ${endpointCard({
    method: "GET",
    path: "/api/files/:id",
    note: `Streams inline by default. Add ${code(
      "?download=1"
    )} to force an attachment. ${code("Range")} requests return ${code(
      "206"
    )} with a ${code("Content-Range")} header.`,
  })}

  ${endpointCard({
    method: "DELETE",
    path: "/api/files/:id",
    blocks: [
      {
        label: "Response",
        code: `{ <span class="text-tertiary">"object"</span>: <span class="text-primary-fixed-dim">"file"</span>, <span class="text-tertiary">"deleted"</span>: <span class="text-primary-fixed-dim">true</span> }`,
      },
    ],
  })}

  ${endpointCard({
    method: "DELETE",
    path: "/api/files",
    note: "Bulk delete, up to 1000 IDs per call.",
    blocks: [
      {
        label: "Request",
        code: `<span class="text-primary">curl</span> -X DELETE \\
  <span class="text-primary-fixed-dim">"https://cdn.pushkarsingh4343.workers.dev/api/files"</span> \\
  -H <span class="text-method-post">"Authorization: Bearer YOUR_API_KEY"</span> \\
  -H <span class="text-tertiary">"Content-Type: application/json"</span> \\
  -d <span class="text-text-secondary">'{"ids":["abc123","def456"]}'</span>`,
      },
    ],
  })}

  <h2 class="font-headline-md text-headline-md text-text-primary font-semibold mt-space-2xl mb-space-md">Expiration values</h2>

  <div class="rounded-xl bg-surface-card border border-border-subtle overflow-hidden">
    <table class="w-full">
      <thead>
        <tr class="border-b border-border-subtle bg-surface-base">
          <th class="text-left px-space-lg py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Value</th>
          <th class="text-left px-space-lg py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Lifetime</th>
        </tr>
      </thead>
      <tbody class="font-body-md text-body-md text-text-secondary">
        ${[
          ["1h", "1 hour"],
          ["6h", "6 hours"],
          ["12h", "12 hours"],
          ["1d", "1 day"],
          ["3d", "3 days"],
          ["7d", "7 days — the default, and fixed for public uploads"],
          ["30d", "30 days"],
          ["90d", "90 days"],
          ["never", "No expiration"],
        ]
          .map(
            ([value, meaning]) => `<tr class="border-b border-border-subtle/60 last:border-0">
          <td class="px-space-lg py-space-sm font-label-code-md text-body-sm text-primary">${value}</td>
          <td class="px-space-lg py-space-sm">${meaning}</td>
        </tr>`
          )
          .join("\n        ")}
      </tbody>
    </table>
  </div>

</div>
</div>
</main>

${SITE_FOOTER}

</body>
</html>`
  );
}

/* ============================================================
   PREVIEW PAGE
   ============================================================ */

function previewGlyph(type) {
  type = String(type || "").toLowerCase();
  if (type.startsWith("image/")) return "image";
  if (type.startsWith("video/")) return "movie";
  if (type.startsWith("audio/")) return "graphic_eq";
  if (type.includes("pdf")) return "picture_as_pdf";
  if (type.includes("zip") || type.includes("compressed")) return "folder_zip";
  if (type.includes("json") || type.startsWith("text/")) return "terminal";
  return "draft";
}

function previewPage(file) {
  const raw = `${PUBLIC_PREFIX}${encodeURIComponent(file.id)}?raw=1`;
  const download = `${PUBLIC_PREFIX}${encodeURIComponent(file.id)}?download=1`;
  const type = String(file.type || "").toLowerCase();
  const name = htmlEscape(file.name);

  let media;

  if (type.startsWith("image/")) {
    media = `<img class="max-w-full max-h-[72vh] rounded-lg block" src="${raw}" alt="${name}">`;
  } else if (type.startsWith("video/")) {
    media = `<video class="max-w-full max-h-[72vh] rounded-lg block" src="${raw}" controls playsinline preload="metadata"></video>`;
  } else if (type.startsWith("audio/")) {
    media = `<audio class="w-full max-w-lg" src="${raw}" controls preload="metadata"></audio>`;
  } else if (type.includes("pdf")) {
    media = `<iframe class="w-full h-[74vh] rounded-lg bg-surface-card border-0" src="${raw}" title="${name}"></iframe>`;
  } else if (
    type.startsWith("text/") ||
    type.includes("json") ||
    type.includes("csv") ||
    type.includes("xml")
  ) {
    media = `<pre id="text" class="w-full max-h-[70vh] overflow-auto m-0 font-label-code-lg text-body-sm text-text-secondary leading-relaxed whitespace-pre-wrap break-words">Loading…</pre>`;
  } else {
    media = `<div class="flex flex-col items-center gap-space-sm py-space-2xl text-center">
      <div class="w-12 h-12 rounded-xl bg-surface-raised border border-border-highlight flex items-center justify-center text-text-muted">
        <span class="material-symbols-outlined text-[24px]">visibility_off</span>
      </div>
      <p class="font-body-md text-body-md text-text-secondary">No preview for this file type. Download it to open.</p>
    </div>`;
  }

  return htmlPage(
`<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${name} — Content Delivery</title>
${HEAD_ASSETS}
</head>
<body class="bg-surface-deep font-body-md text-body-md text-on-surface antialiased">

${SITE_HEADER}

<main class="w-full pt-16">
<div class="relative overflow-hidden">
<div class="absolute -top-40 left-1/2 -translate-x-1/2 w-[720px] h-[300px] bg-primary/10 blur-[130px] pointer-events-none rounded-full"></div>

<div class="max-w-[960px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop py-space-2xl relative">

  <div class="rounded-2xl bg-surface-card border border-border-subtle overflow-hidden shadow-2xl">
    <div class="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-primary/40 to-transparent"></div>

    <div class="flex flex-wrap items-center gap-space-md px-space-lg py-space-md border-b border-border-subtle bg-surface-base">
      <div class="w-10 h-10 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary shrink-0">
        <span class="material-symbols-outlined text-[20px]">${previewGlyph(
          file.type
        )}</span>
      </div>

      <div class="min-w-0 flex-1">
        <p class="font-headline-sm text-headline-sm text-text-primary truncate" title="${name}">${name}</p>
        <div class="flex flex-wrap items-center gap-space-xs font-label-code-md text-caption text-text-muted mt-0.5">
          <span>${formatBytes(file.size)}</span><span>&bull;</span>
          <span>${htmlEscape(file.type)}</span><span>&bull;</span>
          <span class="text-primary">${relativeTime(file.expiresAt)}</span>
        </div>
      </div>

      <div class="flex items-center gap-space-xs w-full sm:w-auto">
        <a href="${download}" download
          class="flex-1 sm:flex-none justify-center px-space-lg py-space-xs rounded-lg bg-primary text-white font-headline-sm text-body-sm hover:bg-primary-container transition-all inline-flex items-center gap-space-xs shadow-lg shadow-primary/20">
          <span class="material-symbols-outlined text-[18px]">download</span>
          Download
        </a>
        <a href="${raw}" target="_blank" rel="noopener"
          class="flex-1 sm:flex-none justify-center px-space-md py-space-xs rounded-lg bg-surface-raised border border-border-subtle text-text-primary font-headline-sm text-body-sm hover:border-border-highlight transition-all inline-flex items-center gap-space-xs">
          <span class="material-symbols-outlined text-[18px]">open_in_new</span>
          Raw
        </a>
      </div>
    </div>

    <div class="flex items-center justify-center p-space-lg bg-surface-deep min-h-[240px]">${media}</div>

    <div class="flex items-center gap-space-xs px-space-lg py-space-md border-t border-border-subtle bg-surface-base">
      <input id="link" type="text" readonly aria-label="Link to this file"
        class="flex-1 min-w-0 h-10 px-space-md rounded-lg bg-surface-deep border border-border-subtle text-text-secondary font-label-code-md text-body-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
      <button id="copy" type="button"
        class="h-10 px-space-md rounded-lg bg-surface-raised border border-border-subtle text-text-primary font-headline-sm text-body-sm hover:border-primary hover:text-primary transition-all inline-flex items-center gap-space-xs shrink-0">
        <span class="material-symbols-outlined text-[18px]">content_copy</span>
        <span id="copy-label">Copy link</span>
      </button>
    </div>
  </div>

  <p class="mt-space-lg text-center font-body-sm text-body-sm text-text-muted">
    This link expires on its own.
    <a class="text-text-secondary hover:text-primary transition-colors" href="/#share">Share a file of your own</a>
  </p>

</div>
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
   STATUS PAGES
   ============================================================ */

function statusPage({ status, code, title, message, tone = "primary" }) {
  return htmlPage(
`<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${title} — Content Delivery</title>
${HEAD_ASSETS}
</head>
<body class="bg-surface-deep font-body-md text-body-md text-on-surface antialiased">

${SITE_HEADER}

<main class="w-full pt-16">
<div class="relative overflow-hidden min-h-[70vh] flex items-center justify-center px-gutter-mobile">
<div class="absolute -top-20 left-1/2 -translate-x-1/2 w-[620px] h-[300px] bg-${tone}/10 blur-[130px] pointer-events-none rounded-full"></div>

<div class="relative text-center max-w-md py-space-3xl">
  <div class="w-12 h-12 rounded-xl bg-surface-raised border border-border-highlight flex items-center justify-center text-${tone} mx-auto mb-space-md">
    <span class="material-symbols-outlined text-[24px]">${
      status === 410 ? "hourglass_disabled" : "search_off"
    }</span>
  </div>

  <div class="font-eyebrow text-eyebrow uppercase tracking-widest text-${tone} mb-space-xs">${code}</div>

  <h1 class="font-headline-lg text-headline-lg text-text-primary font-semibold tracking-tight mb-space-sm">${title}</h1>

  <p class="font-body-md text-body-md text-text-secondary leading-relaxed mb-space-lg">${message}</p>

  <a class="px-space-lg py-space-sm rounded-lg bg-primary text-white font-headline-sm text-body-md hover:bg-primary-container transition-all inline-flex items-center gap-space-xs shadow-lg shadow-primary/20" href="/">
    <span class="material-symbols-outlined text-[18px]">arrow_back</span>
    Back to Content Delivery
  </a>
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
    title: "That page doesn't exist",
    message:
      "The link may be wrong, or the file may have been deleted. Head back to the homepage to keep going.",
  });
}

function expiredPage() {
  return statusPage({
    status: 410,
    code: "410",
    title: "This link has expired",
    message:
      "Public files are kept for seven days and then deleted. Ask whoever sent it to upload the file again.",
    tone: "method-post",
  });
}

/* ============================================================
   DASHBOARD
   ============================================================ */

function dashboardPage() {
  return htmlPage(
`<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — Content Delivery</title>
<meta name="description" content="Manage files in your Content Delivery bucket.">
${HEAD_ASSETS}
</head>
<body class="bg-surface-deep font-body-md text-body-md text-on-surface antialiased">

<a class="skip" href="#main">Skip to content</a>

<header class="fixed top-0 left-0 right-0 z-50 bg-surface-deep/85 backdrop-blur-xl border-b border-border-subtle">
  <div class="h-16 max-w-[1240px] mx-auto px-gutter-mobile lg:px-gutter-desktop flex items-center justify-between gap-space-md">
    <a class="flex items-center gap-space-xs min-w-0" href="/">
      <div class="w-8 h-8 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center shrink-0">
        <span class="material-symbols-outlined text-primary text-[18px]">cloud_sync</span>
      </div>
      <div class="min-w-0">
        <div class="font-headline-sm text-headline-sm text-text-primary tracking-tight truncate">Content Delivery</div>
        <div class="hidden sm:block font-label-code-md text-caption text-text-muted truncate">bucket: ${BUCKET_NAME} · v${VERSION}</div>
      </div>
    </a>

    <div class="flex items-center gap-space-xs">
      <a href="/docs" class="hidden sm:inline-flex px-space-md py-space-xs rounded-lg bg-surface-card border border-border-subtle text-text-secondary font-body-md text-body-sm hover:text-text-primary hover:border-border-highlight transition-all items-center gap-1.5">
        <span class="material-symbols-outlined text-[16px]">description</span>
        API docs
      </a>
      <button id="refresh" type="button" class="px-space-md py-space-xs rounded-lg bg-surface-card border border-border-subtle text-text-secondary font-body-md text-body-sm hover:text-text-primary hover:border-border-highlight transition-all inline-flex items-center gap-1.5">
        <span class="material-symbols-outlined text-[16px]">refresh</span>
        Refresh
      </button>
      <button id="logout" type="button" class="px-space-md py-space-xs rounded-lg bg-method-delete/10 border border-method-delete/30 text-method-delete font-body-md text-body-sm hover:border-method-delete/60 transition-all inline-flex items-center gap-1.5">
        <span class="material-symbols-outlined text-[16px]">logout</span>
        <span class="hidden sm:inline">Log out</span>
      </button>
    </div>
  </div>
</header>

<main id="main" class="w-full pt-16">
<div class="relative overflow-hidden">
<div class="absolute -top-40 left-1/2 -translate-x-1/2 w-[720px] h-[300px] bg-primary/10 blur-[130px] pointer-events-none rounded-full"></div>

<div class="max-w-[1240px] w-full mx-auto px-gutter-mobile lg:px-gutter-desktop py-space-xl relative space-y-space-md">

  <!-- stats -->
  <section class="grid grid-cols-2 lg:grid-cols-4 gap-space-md" aria-label="Storage statistics">
    <div class="relative rounded-xl bg-surface-card border border-border-subtle p-space-lg overflow-hidden">
      <div class="absolute inset-x-space-lg top-0 h-[1px] bg-gradient-to-r from-primary/60 to-transparent"></div>
      <div class="font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Files</div>
      <div id="stat-files" class="mt-space-xs font-label-code-lg text-headline-md text-text-primary font-bold">—</div>
    </div>
    <div class="relative rounded-xl bg-surface-card border border-border-subtle p-space-lg overflow-hidden">
      <div class="absolute inset-x-space-lg top-0 h-[1px] bg-gradient-to-r from-primary/60 to-transparent"></div>
      <div class="font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Storage used</div>
      <div id="stat-storage" class="mt-space-xs font-label-code-lg text-headline-md text-text-primary font-bold">—</div>
    </div>
    <div class="relative rounded-xl bg-surface-card border border-border-subtle p-space-lg overflow-hidden">
      <div class="absolute inset-x-space-lg top-0 h-[1px] bg-gradient-to-r from-tertiary/60 to-transparent"></div>
      <div class="font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Public</div>
      <div id="stat-public" class="mt-space-xs font-label-code-lg text-headline-md text-tertiary font-bold">—</div>
    </div>
    <div class="relative rounded-xl bg-surface-card border border-border-subtle p-space-lg overflow-hidden">
      <div class="absolute inset-x-space-lg top-0 h-[1px] bg-gradient-to-r from-method-post/60 to-transparent"></div>
      <div class="font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Expired</div>
      <div id="stat-expired" class="mt-space-xs font-label-code-lg text-headline-md text-text-primary font-bold">—</div>
    </div>
  </section>

  <!-- upload -->
  <section class="relative rounded-2xl bg-surface-card border border-border-subtle p-space-sm sm:p-space-lg shadow-2xl group" aria-label="Upload">
    <div class="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-primary/40 to-transparent"></div>

    <div id="drop-target" class="relative flex flex-col items-center justify-center p-space-xl rounded-xl border-2 border-dashed border-border-subtle bg-surface-deep/90 hover:border-primary/60 transition-all duration-200 text-center">
      <div class="w-12 h-12 rounded-xl bg-surface-raised border border-border-highlight flex items-center justify-center mb-space-sm text-primary">
        <span class="material-symbols-outlined text-[24px]">upload_file</span>
      </div>

      <p class="font-headline-sm text-headline-sm text-text-primary">Drop a file, or browse</p>
      <p class="font-body-md text-body-md text-text-secondary mt-1">Streamed straight to R2 — no size cap on this side.</p>

      <input id="file-input" type="file" aria-label="Choose a file"
        class="w-full max-w-xl mt-space-md px-space-md py-space-xs rounded-lg bg-surface-deep border border-border-subtle text-text-secondary font-body-md text-body-sm file:mr-3 file:px-space-md file:py-1 file:rounded file:border-0 file:bg-surface-raised file:text-text-primary file:font-body-md file:text-body-sm file:cursor-pointer">

      <div class="w-full max-w-xl mt-space-sm grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-space-xs">
        <select id="expiry" aria-label="Expiration"
          class="h-10 px-space-md rounded-lg bg-surface-deep border border-border-subtle text-text-primary font-body-md text-body-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
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

        <button id="upload-button" type="button"
          class="h-10 px-space-lg rounded-lg bg-primary text-white font-headline-sm text-body-md hover:bg-primary-container transition-all inline-flex items-center justify-center gap-space-xs shadow-lg shadow-primary/20 disabled:opacity-60">
          <span class="material-symbols-outlined text-[18px]">arrow_upward</span>
          Upload
        </button>
      </div>

      <div id="progress" class="mt-space-sm min-h-[18px] font-label-code-md text-caption text-text-muted" role="status"></div>
    </div>
  </section>

  <!-- files -->
  <section class="rounded-2xl bg-surface-card border border-border-subtle overflow-hidden" aria-label="Files">
    <div class="flex items-center justify-between gap-space-md px-space-lg py-space-md border-b border-border-subtle bg-surface-base">
      <div class="flex items-center gap-space-sm">
        <span class="font-headline-sm text-headline-sm text-text-primary">Files</span>
        <span id="result-count" class="font-label-code-md text-caption text-text-muted">—</span>
      </div>
    </div>

    <div id="bulk" class="hidden items-center justify-between gap-space-md px-space-lg py-space-xs border-b border-primary/25 bg-primary/5">
      <span id="selected-text" class="font-label-code-md text-caption text-primary">0 selected</span>
      <div class="flex items-center gap-space-xs">
        <button id="clear-selection" type="button" class="px-space-sm py-1 rounded bg-surface-raised border border-border-subtle text-text-secondary font-body-md text-body-sm hover:text-text-primary transition-colors">Clear</button>
        <button id="bulk-delete" type="button" class="px-space-sm py-1 rounded bg-method-delete/10 border border-method-delete/30 text-method-delete font-body-md text-body-sm hover:border-method-delete/60 transition-colors">Delete selected</button>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-[1fr_180px_150px] gap-space-xs px-space-lg py-space-sm border-b border-border-subtle">
      <input id="search" placeholder="Search by filename…" aria-label="Search files"
        class="h-10 px-space-md rounded-lg bg-surface-deep border border-border-subtle text-text-primary font-body-md text-body-sm placeholder:text-text-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
      <select id="type-filter" aria-label="Filter by type"
        class="h-10 px-space-md rounded-lg bg-surface-deep border border-border-subtle text-text-primary font-body-md text-body-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
        <option value="">All types</option>
        <option value="image/">Images</option>
        <option value="video/">Videos</option>
        <option value="audio/">Audio</option>
        <option value="application/pdf">PDF</option>
        <option value="text/">Text</option>
        <option value="application/zip">ZIP</option>
      </select>
      <select id="sort" aria-label="Sort by"
        class="h-10 px-space-md rounded-lg bg-surface-deep border border-border-subtle text-text-primary font-body-md text-body-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/40 transition-all">
        <option value="uploaded">Newest first</option>
        <option value="name">Name</option>
        <option value="size">Size</option>
      </select>
    </div>

    <div class="overflow-x-auto">
      <table class="w-full min-w-[940px]">
        <thead>
          <tr class="border-b border-border-subtle bg-surface-base">
            <th class="w-10 px-space-md py-space-sm"><input id="select-all" type="checkbox" aria-label="Select all" class="rounded border-border-highlight bg-surface-deep text-primary focus:ring-primary/40"></th>
            <th class="text-left px-space-md py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">File</th>
            <th class="text-left px-space-md py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Size</th>
            <th class="text-left px-space-md py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Uploaded</th>
            <th class="text-left px-space-md py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Expires</th>
            <th class="text-left px-space-md py-space-sm font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </section>

</div>
</div>
</main>

<div id="toast" class="hidden fixed right-space-md bottom-space-md z-[80] max-w-sm px-space-md py-space-sm rounded-lg bg-surface-raised border border-border-subtle border-l-4 border-l-primary shadow-2xl font-body-md text-body-sm text-text-primary" role="status"></div>

<div id="modal" class="hidden fixed inset-0 z-[90] items-center justify-center p-space-md bg-black/70 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="File information">
  <div class="w-full max-w-2xl max-h-[88vh] overflow-auto rounded-2xl bg-surface-card border border-border-highlight p-space-lg shadow-2xl rise">
    <div class="flex items-center justify-between mb-space-md">
      <span class="font-headline-sm text-headline-sm text-text-primary">File information</span>
      <button id="modal-close" type="button" aria-label="Close" class="w-8 h-8 rounded bg-surface-raised border border-border-subtle flex items-center justify-center text-text-secondary hover:text-primary transition-colors">
        <span class="material-symbols-outlined text-[18px]">close</span>
      </button>
    </div>
    <div id="modal-body" class="grid grid-cols-1 sm:grid-cols-2 gap-space-xs"></div>
  </div>
</div>

<script>
var files = [];
var selected = {};
var timer = null;

var BTN =
  "px-space-sm py-1 rounded bg-surface-raised border border-border-subtle font-body-md text-body-sm text-text-secondary hover:text-primary hover:border-primary transition-colors";

/* ---------- helpers ---------- */

function esc(value) {
  var div = document.createElement("div");
  div.textContent = String(value == null ? "" : value);
  return div.innerHTML;
}

function formatBytes(bytes) {
  bytes = Number(bytes) || 0;
  if (!bytes) return "0 B";
  var units = ["B", "KB", "MB", "GB", "TB", "PB"];
  var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + " " + units[i];
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function relative(value) {
  var diff = new Date(value).getTime() - Date.now();
  if (diff <= 0) return "expired";

  var minutes = Math.floor(diff / 60000);
  if (minutes < 60) return "in " + minutes + "m";

  var hours = Math.floor(minutes / 60);
  if (hours < 24) return "in " + hours + "h";

  return "in " + Math.floor(hours / 24) + "d";
}

function glyph(type) {
  type = String(type || "").toLowerCase();
  if (type.indexOf("image/") === 0) return "image";
  if (type.indexOf("video/") === 0) return "movie";
  if (type.indexOf("audio/") === 0) return "graphic_eq";
  if (type.indexOf("pdf") > -1) return "picture_as_pdf";
  if (type.indexOf("zip") > -1 || type.indexOf("compressed") > -1) return "folder_zip";
  if (type.indexOf("json") > -1 || type.indexOf("text/") === 0) return "terminal";
  return "draft";
}

function selectedIds() {
  return Object.keys(selected);
}

function toast(message, isError) {
  var element = document.getElementById("toast");

  element.textContent = message;
  element.classList.remove("hidden", "border-l-primary", "border-l-method-delete");
  element.classList.add(isError ? "border-l-method-delete" : "border-l-primary");

  clearTimeout(window.__toast);
  window.__toast = setTimeout(function () {
    element.classList.add("hidden");
  }, 3500);
}

/* ---------- API ---------- */

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

/* ---------- list ---------- */

function skeleton() {
  var rows = "";

  for (var i = 0; i < 5; i++) {
    rows +=
      '<tr class="border-b border-border-subtle/60">' +
      '<td class="px-space-md py-space-sm"></td>' +
      '<td class="px-space-md py-space-sm"><div class="h-4 w-2/3 rounded bg-surface-raised animate-pulse"></div></td>' +
      '<td class="px-space-md py-space-sm"><div class="h-4 w-12 rounded bg-surface-raised animate-pulse"></div></td>' +
      '<td class="px-space-md py-space-sm"><div class="h-4 w-24 rounded bg-surface-raised animate-pulse"></div></td>' +
      '<td class="px-space-md py-space-sm"><div class="h-4 w-14 rounded bg-surface-raised animate-pulse"></div></td>' +
      '<td class="px-space-md py-space-sm"><div class="h-4 w-40 rounded bg-surface-raised animate-pulse"></div></td>' +
      "</tr>";
  }

  return rows;
}

function emptyRow(title, text) {
  return (
    '<tr><td colspan="6">' +
    '<div class="flex flex-col items-center gap-space-xs py-space-3xl text-center">' +
    '<div class="w-12 h-12 rounded-xl bg-surface-raised border border-border-highlight flex items-center justify-center text-text-muted">' +
    '<span class="material-symbols-outlined text-[24px]">inbox</span></div>' +
    '<p class="font-headline-sm text-headline-sm text-text-primary">' + title + "</p>" +
    '<p class="font-body-md text-body-md text-text-secondary">' + text + "</p>" +
    "</div></td></tr>"
  );
}

function loadFiles() {
  var body = document.getElementById("rows");
  body.innerHTML = skeleton();

  var params = new URLSearchParams({
    limit: "1000",
    sort: document.getElementById("sort").value,
    order: "desc",
  });

  var search = document.getElementById("search").value.trim();
  var type = document.getElementById("type-filter").value;

  if (search) params.set("search", search);
  if (type) params.set("type", type);

  return api("/api/files?" + params)
    .then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok) throw new Error((data.error && data.error.message) || "Failed to load files.");
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
    files.length + (files.length === 1 ? " result" : " results");

  if (!files.length) {
    body.innerHTML = emptyRow(
      "Nothing here yet",
      "Upload your first file above and it will show up in this list."
    );
    updateBulk();
    return;
  }

  body.innerHTML = "";

  files.forEach(function (file) {
    var tr = document.createElement("tr");
    tr.className = "border-b border-border-subtle/60 hover:bg-surface-raised/40 transition-colors";

    var expiry = file.expires_at
      ? '<span class="px-space-xs py-0.5 rounded bg-method-post/15 text-method-post font-label-code-md text-caption">' +
        relative(file.expires_at) + "</span>"
      : '<span class="px-space-xs py-0.5 rounded bg-primary/15 text-primary font-label-code-md text-caption">never</span>';

    var badge =
      file.visibility === "public"
        ? '<span class="ml-space-xs px-1.5 py-0.5 rounded bg-tertiary/15 text-tertiary font-label-code-md text-[10px] uppercase tracking-wider">public</span>'
        : "";

    tr.innerHTML =
      '<td class="px-space-md py-space-sm align-middle">' +
        '<input type="checkbox" data-select="' + esc(file.id) + '" ' +
        (selected[file.id] ? "checked" : "") +
        ' aria-label="Select file" class="rounded border-border-highlight bg-surface-deep text-primary focus:ring-primary/40"></td>' +
      '<td class="px-space-md py-space-sm">' +
        '<div class="flex items-center gap-space-sm min-w-0">' +
          '<div class="w-9 h-9 rounded-lg bg-surface-raised border border-border-highlight flex items-center justify-center text-primary shrink-0">' +
            '<span class="material-symbols-outlined text-[18px]">' + glyph(file.content_type) + "</span></div>" +
          '<div class="min-w-0">' +
            '<p class="font-body-md text-body-md text-text-primary font-medium truncate max-w-[260px]" title="' + esc(file.name) + '">' + esc(file.name) + "</p>" +
            '<p class="font-label-code-md text-caption text-text-muted truncate">' + esc(file.content_type) + badge + "</p>" +
          "</div></div></td>" +
      '<td class="px-space-md py-space-sm font-label-code-md text-caption text-text-secondary whitespace-nowrap">' + formatBytes(file.size) + "</td>" +
      '<td class="px-space-md py-space-sm font-label-code-md text-caption text-text-secondary whitespace-nowrap">' + formatDate(file.uploaded_at) + "</td>" +
      '<td class="px-space-md py-space-sm whitespace-nowrap">' + expiry + "</td>" +
      '<td class="px-space-md py-space-sm">' +
        '<div class="flex items-center gap-space-2xs">' +
          '<button class="' + BTN + '" data-open="' + esc(file.id) + '">Open</button>' +
          '<button class="' + BTN + '" data-download="' + esc(file.id) + '">Download</button>' +
          (file.public_url
            ? '<button class="' + BTN + '" data-copy="' + esc(file.id) + '">Copy link</button>'
            : "") +
          '<button class="' + BTN + '" data-info="' + esc(file.id) + '">Info</button>' +
          '<button class="px-space-sm py-1 rounded bg-method-delete/10 border border-method-delete/30 font-body-md text-body-sm text-method-delete hover:border-method-delete/60 transition-colors" data-delete="' + esc(file.id) + '">Delete</button>' +
        "</div></td>";

    body.appendChild(tr);
  });

  updateBulk();
}

/* ---------- stats ---------- */

function loadStats() {
  return api("/api/stats")
    .then(function (response) {
      return response.ok ? response.json() : null;
    })
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

  button.disabled = true;
  progress.textContent = "uploading " + file.name + "…";

  var url =
    "/api/upload?" +
    new URLSearchParams({
      filename: file.name,
      expires: document.getElementById("expiry").value,
    });

  api(url, {
    method: "PUT",
    headers: { "Content-Type": file.type || "application/octet-stream" },
    body: file,
  })
    .then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok) throw new Error((data.error && data.error.message) || "Upload failed.");
        return data;
      });
    })
    .then(function () {
      progress.textContent = "upload complete";
      toast("File uploaded.");
      input.value = "";
      return refreshAll();
    })
    .catch(function (error) {
      progress.textContent = "";
      toast(error.message, true);
    })
    .then(function () {
      button.disabled = false;
    });
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
    .catch(function (error) {
      toast(error.message, true);
    });
}

function copyPublic(id) {
  var file = files.filter(function (item) { return item.id === id; })[0];
  if (!file || !file.public_url) return;

  var url = location.origin + file.public_url;

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(
      function () { toast("Link copied."); },
      function () { toast(url); }
    );
  } else {
    toast(url);
  }
}

/* ---------- bulk ---------- */

function updateBulk() {
  var bar = document.getElementById("bulk");
  var count = selectedIds().length;

  document.getElementById("selected-text").textContent = count + " selected";

  bar.classList.toggle("hidden", count === 0);
  bar.classList.toggle("flex", count > 0);
}

function bulkDelete() {
  var ids = selectedIds();
  if (!ids.length) return;
  if (!confirm("Delete " + ids.length + " selected files?")) return;

  api("/api/files", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids: ids }),
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
    .catch(function (error) {
      toast(error.message, true);
    });
}

/* ---------- info modal ---------- */

function metaCell(label, value, wide) {
  return (
    '<div class="rounded-lg bg-surface-deep border border-border-subtle p-space-md' +
    (wide ? ' sm:col-span-2' : "") + '">' +
    '<div class="font-eyebrow text-eyebrow uppercase tracking-wider text-text-muted">' + label + "</div>" +
    '<div class="mt-1 font-body-md text-body-sm text-text-primary break-all">' + value + "</div></div>"
  );
}

function showInfo(id) {
  var file = files.filter(function (item) { return item.id === id; })[0];
  if (!file) return;

  var body = document.getElementById("modal-body");

  body.innerHTML =
    metaCell("Name", esc(file.name)) +
    metaCell("Size", formatBytes(file.size)) +
    metaCell("Content type", esc(file.content_type)) +
    metaCell("Visibility", esc(file.visibility || "private")) +
    metaCell("Uploaded", formatDate(file.uploaded_at)) +
    metaCell("Expires", file.expires_at ? formatDate(file.expires_at) : "Never") +
    metaCell("ID", esc(file.id), true) +
    metaCell("ETag", esc(file.etag || "—"), true) +
    metaCell("API URL", esc(location.origin + "/api/files/" + file.id), true) +
    (file.public_url
      ? metaCell("Public link", esc(location.origin + file.public_url), true)
      : "");

  var modal = document.getElementById("modal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
}

function closeModal() {
  var modal = document.getElementById("modal");
  modal.classList.add("hidden");
  modal.classList.remove("flex");
}

/* ---------- wiring ---------- */

document.getElementById("rows").addEventListener("click", function (event) {
  var button = event.target.closest("button");
  if (!button) return;

  var id;

  if ((id = button.getAttribute("data-open"))) {
    window.open("/api/files/" + encodeURIComponent(id), "_blank");
  } else if ((id = button.getAttribute("data-download"))) {
    window.open("/api/files/" + encodeURIComponent(id) + "?download=1", "_blank");
  } else if ((id = button.getAttribute("data-copy"))) {
    copyPublic(id);
  } else if ((id = button.getAttribute("data-info"))) {
    showInfo(id);
  } else if ((id = button.getAttribute("data-delete"))) {
    deleteFile(id);
  }
});

document.getElementById("rows").addEventListener("change", function (event) {
  var id = event.target.getAttribute("data-select");
  if (!id) return;

  if (event.target.checked) selected[id] = true;
  else delete selected[id];

  updateBulk();
});

document.getElementById("select-all").addEventListener("change", function () {
  if (this.checked) {
    files.forEach(function (file) { selected[file.id] = true; });
  } else {
    selected = {};
  }
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

/* ---------- drag and drop ---------- */

(function () {
  var target = document.getElementById("drop-target");
  var input = document.getElementById("file-input");

  ["dragenter", "dragover"].forEach(function (name) {
    target.addEventListener(name, function (event) {
      event.preventDefault();
      target.classList.add("border-primary", "bg-primary/5");
    });
  });

  target.addEventListener("dragleave", function (event) {
    if (!target.contains(event.relatedTarget)) {
      target.classList.remove("border-primary", "bg-primary/5");
    }
  });

  target.addEventListener("drop", function (event) {
    event.preventDefault();
    target.classList.remove("border-primary", "bg-primary/5");
    if (event.dataTransfer.files.length) input.files = event.dataTransfer.files;
  });
})();

refreshAll();
</script>

</body>
</html>`
  );
}
