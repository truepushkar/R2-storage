
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
<script>${CLIENT_DASH}</script>
</body>
</html>`
  );
}
