(function () {
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
        "curl -X PUT \"" + location.origin + "/api/upload?filename=clip.mp4&expires=7d\" \\",
        "  -H \"authorization: Bearer $KEY\" \\",
        "  -H \"content-type: video/mp4\" \\",
        "  --data-binary @clip.mp4"
      ]),
      response: joinLines([
        "{",
        "  \"id\": \"a4e3c1...\",",
        "  \"name\": \"clip.mp4\",",
        "  \"size\": 184320000,",
        "  \"expires_at\": \"2026-11-06T14:43Z\",",
        "  \"download_url\": \"/api/files/a4e3c1...\"",
        "}"
      ])
    },
    {
      verb: "PUT",
      path: "/public/upload",
      tag: "no key, fixed 7d",
      request: joinLines([
        "curl -X PUT \"" + location.origin + "/public/upload?filename=notes.txt\" \\",
        "  -H \"content-type: text/plain\" \\",
        "  --data-binary @notes.txt"
      ]),
      response: joinLines([
        "{",
        "  \"id\": \"abc123...\",",
        "  \"name\": \"notes.txt\",",
        "  \"expires_at\": \"2026-11-06T14:43Z\",",
        "  \"url\": \"" + location.origin + "/f/abc123...\"",
        "}"
      ])
    },
    {
      verb: "GET",
      path: "/api/files",
      tag: "list + search",
      request: joinLines([
        "curl \"" + location.origin + "/api/files?search=clip&sort=size&order=desc\" \\",
        "  -H \"authorization: Bearer $KEY\""
      ]),
      response: joinLines([
        "{",
        "  \"data\": [ { \"id\": \"a4e3c1...\", \"name\": \"clip.mp4\", \"size\": 184320000 } ],",
        "  \"pagination\": { \"cursor\": null, \"has_more\": false },",
        "  \"count\": 1",
        "}"
      ])
    },
    {
      verb: "GET",
      path: "/api/files/:id",
      tag: "range bytes",
      request: joinLines([
        "curl \"" + location.origin + "/api/files/a4e3c1...\" \\",
        "  -H \"range: bytes=0-1023\" \\",
        "  -H \"authorization: Bearer $KEY\""
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
        "curl -X DELETE \"" + location.origin + "/api/files\" \\",
        "  -H \"authorization: Bearer $KEY\" \\",
        "  -H \"content-type: application/json\" \\",
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
      else if (/^\s/.test(line)) out += '<span class="n">' + safe + "</span>" + NL;
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
