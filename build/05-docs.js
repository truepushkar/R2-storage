
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
