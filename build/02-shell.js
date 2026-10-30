
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

const JK_STYLE = "__CSS__";

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
