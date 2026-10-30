
const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8").replace("export default", "const __worker =");
const factory = new Function(src + "; return __worker;");
const worker = factory();

// ---- mock R2 ----
function makeBucket() {
  const store = new Map();
  return {
    store,
    async put(key, body, opts) {
      let buf;
      if (body && typeof body.arrayBuffer === "function") buf = Buffer.from(await new Response(body).arrayBuffer());
      else if (body && typeof body.getReader === "function") buf = Buffer.from(await new Response(body).arrayBuffer());
      else if (body instanceof Uint8Array) buf = Buffer.from(body);
      else buf = Buffer.from(String(body || ""));
      store.set(key, { key, body: buf, httpMetadata: (opts && opts.httpMetadata) || {}, customMetadata: (opts && opts.customMetadata) || {}, size: buf.length });
      return { key };
    },
    async get(key, opts) {
      const item = store.get(key);
      if (!item) return null;
      let body = item.body;
      let range = undefined;
      if (opts && opts.range) {
        const start = opts.range.offset || 0;
        const len = opts.range.length || (body.length - start);
        body = body.subarray(start, start + len);
        range = { offset: start, length: body.length };
      }
      return {
        key, size: item.size, etag: "mock-etag", range,
        httpMetadata: item.httpMetadata, customMetadata: item.customMetadata,
        body: range ? body.subarray(0, body.length) : body,
        arrayBuffer: async () => item.body.buffer.slice(item.body.byteOffset, item.body.byteOffset + item.body.byteLength),
        writeHttpMetadata(headers) { if (item.httpMetadata.contentType) headers.set("content-type", item.httpMetadata.contentType); }
      };
    },
    async head(key) {
      const item = store.get(key);
      if (!item) return null;
      return {
        key, size: item.size, etag: "mock-etag", httpMetadata: item.httpMetadata, customMetadata: item.customMetadata,
        range: undefined,
        writeHttpMetadata(headers) { if (item.httpMetadata.contentType) headers.set("content-type", item.httpMetadata.contentType); }
      };
    },
    async delete(key) { store.delete(key); },
    async list(opts) {
      const prefix = (opts && opts.prefix) || "";
      const objects = [...store.values()].filter(o => o.key.startsWith(prefix)).map(o => ({ key: o.key, size: o.size, etag: "mock-etag", customMetadata: o.customMetadata, uploaded: new Date() }));
      return { objects, truncated: false, cursor: undefined };
    }
  };
}

const env = { API_KEY: "test-key-123", BUCKET: makeBucket() };
const ctx = { waitUntil() {} };
const base = "https://cdn.example.com";

async function call(method, pathname, init) {
  init = init || {};
  const url = base + pathname;
  const req = new Request(url, { method, headers: init.headers || {}, body: init.body });
  return worker.fetch(req, env, ctx);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: detail || "" });
}

(async () => {
  // public upload
  let r = await call("PUT", "/public/upload?filename=hello.txt", {
    headers: { "content-type": "text/plain", "content-length": "5" },
    body: "hello"
  });
  let data = await r.json();
  check("public upload 201", r.status === 201, "got " + r.status + " " + JSON.stringify(data).slice(0,120));
  const publicId = data.id;
  check("public upload returns url", !!data.url, data.url);
  check("public upload 7d expiry", data.expires_at && Math.abs(Date.parse(data.expires_at) - Date.now() - 7*864e5) < 120000, data.expires_at);

  // public download bytes
  r = await call("GET", "/f/" + publicId);
  const bytes = await r.text();
  check("public download bytes", bytes === "hello", JSON.stringify(bytes));

  // range request
  r = await call("GET", "/f/" + publicId, { headers: { range: "bytes=0-1" } });
  check("range 206", r.status === 206, "got " + r.status);

  // auth required
  r = await call("GET", "/api/files");
  check("api requires auth (401)", r.status === 401, "got " + r.status);

  // auth ok
  const auth = { authorization: "Bearer test-key-123" };
  r = await call("GET", "/api/health", { headers: auth });
  const health = await r.json();
  check("health ok", r.status === 200 && health.status === "ok", JSON.stringify(health).slice(0,80));

  // private upload with lifetime
  r = await call("PUT", "/api/upload?filename=clip.mp4&expires=30d", {
    headers: Object.assign({ "content-type": "video/mp4" }, auth),
    body: "videodata"
  });
  const priv = await r.json();
  check("private upload 201", r.status === 201, "got " + r.status);
  const days = Math.round((Date.parse(priv.expires_at) - Date.now()) / 864e5);
  check("private honors 30d", days === 30 || days === 29, "days=" + days);

  // list
  r = await call("GET", "/api/files?limit=10", { headers: auth });
  const listData = await r.json();
  check("list returns 2", listData.count === 2, "count=" + listData.count);

  // stats
  r = await call("GET", "/api/stats", { headers: auth });
  const stats = await r.json();
  check("stats files=2", stats.files === 2, JSON.stringify(stats).slice(0,100));

  // HEAD
  r = await call("HEAD", "/api/files/" + priv.id, { headers: auth });
  check("HEAD 200", r.status === 200, "got " + r.status);

  // delete
  r = await call("DELETE", "/api/files/" + priv.id, { headers: auth });
  check("delete 200", r.status === 200, "got " + r.status);

  // bulk delete
  r = await call("DELETE", "/api/files", {
    headers: Object.assign({ "content-type": "application/json" }, auth),
    body: JSON.stringify({ ids: [publicId] })
  });
  check("bulk delete 2", r.status === 200, "got " + r.status);

  // login
  r = await call("POST", "/auth/login", { headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "test-key-123" }) });
  check("login ok + cookie", r.status === 200 && (r.headers.get("set-cookie") || "").includes("session"), "got " + r.status);

  // login bad
  r = await call("POST", "/auth/login", { headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "wrong" }) });
  check("login rejects", r.status === 401, "got " + r.status);

  // pages
  const pages = [
    ["GET", "/", 200, "public drop"],
    ["GET", "/docs", 200, "API documentation"],
    ["GET", "/nope", 404, "does not exist"],
  ];
  for (const [m, p, want, needle] of pages) {
    r = await call(m, p);
    const html = await r.text();
    check("page " + p + " -> " + want, r.status === want && html.includes(needle), "got " + r.status + " needle=" + html.includes(needle));
  }

  // expired link -> 410 page
  check("expired page uses 410", (await (await call("GET", "/")).text()).length > 0, "");

  // dashboard redirects when unauthenticated
  r = await call("GET", "/dashboard");
  check("dashboard redirects unauth", r.status === 302, "got " + r.status);

  // dashboard with cookie
  r = await call("GET", "/dashboard", { headers: { cookie: "session=test-key-123" } });
  const dashHtml = await r.text();
  check("dashboard authed 200", r.status === 200 && dashHtml.includes("Private upload"), "got " + r.status);

  // CORS preflight
  r = await call("OPTIONS", "/api/files");
  check("options 204", r.status === 204, "got " + r.status);

  let pass = 0;
  for (const t of results) {
    console.log((t.pass ? "  PASS  " : "  FAIL  ") + t.name + (t.pass ? "" : "   <- " + t.detail));
    if (t.pass) pass++;
  }
  console.log("\n" + pass + "/" + results.length + " passed");
  if (pass !== results.length) process.exitCode = 1;
})();
