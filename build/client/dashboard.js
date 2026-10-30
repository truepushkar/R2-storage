(function () {
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
