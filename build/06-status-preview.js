
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
