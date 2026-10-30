
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
<script>${CLIENT_HOME}</script>
</body>
</html>`
  );
}
