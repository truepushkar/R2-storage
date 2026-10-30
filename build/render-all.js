const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8").replace("export default", "const __worker =");
const factory = new Function(src + "; return { publicPage: publicPage, docsPage: docsPage, dashboardPage: dashboardPage, previewPage: previewPage, notFoundPage: notFoundPage, expiredPage: expiredPage };");
const m = factory();
(async () => {
  const out = path.join(__dirname, "out");
  fs.mkdirSync(out, { recursive: true });
  const pages = {
    home: m.publicPage(),
    docs: m.docsPage(),
    dashboard: m.dashboardPage(),
    notfound: m.notFoundPage(),
    expired: m.expiredPage(),
    preview: m.previewPage({ id: "abc123", name: "trip-photo.jpg", size: 842113, type: "image/jpeg", expiresAt: new Date(Date.now() + 5 * 864e5).toISOString() })
  };
  for (const key of Object.keys(pages)) {
    const html = await pages[key].text();
    fs.writeFileSync(path.join(out, key + ".html"), html);
    console.log(key, html.length, pages[key].status);
  }
})();