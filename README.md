# R2 Storage API — Cloudflare Worker

A production-ready file storage service built as a single [Cloudflare Worker](https://workers.cloudflare.com/) backed by **Cloudflare R2**. Upload, list, download, and delete files over a clean REST API, with optional browser access via a built-in login + dashboard.

- ✅ Single-file Worker — no build step
- ✅ Direct-to-R2 streaming uploads (raw body **or** multipart/form-data)
- ✅ Automatic file expiration with scheduled garbage collection
- ✅ Bearer-token **or** session-cookie authentication
- ✅ Range requests (supports resumable downloads / video seeking)
- ✅ Built-in landing page, REST docs page, and admin dashboard
- ✅ CORS + security headers, safe filename handling, constant-time auth

> **Version:** `3.0.0`

---

## Table of Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Local development](#local-development)
- [Security notes](#security-notes)
- [License](#license)

---

## Features

| Area          | Detail                                                                 |
| ------------- | ---------------------------------------------------------------------- |
| **Storage**   | Cloudflare R2 (S3-compatible, no egress fees)                          |
| **Uploads**   | Raw `PUT` streaming *or* multipart `POST` — files streamed directly to R2, no size cap |
| **Expiration**| Any of `1h, 6h, 12h, 1d, 3d, 7d, 30d, 90d, never` (default `7d`)      |
| **Auth**      | `Authorization: Bearer <API_KEY>` header **or** HttpOnly session cookie |
| **Listing**   | Pagination, search, type filter, sorting (name/size/uploaded)          |
| **Download**  | Full download or HTTP `Range` (206 Partial Content), `?download=1`     |
| **Delete**    | Single or bulk (up to 1000 IDs per request)                            |
| **UI**        | Auto-generated landing page, `/docs` reference, and `/dashboard` panel |
| **Cleanup**   | Scheduled cron removes expired files automatically                      |

---

## How it works

Every upload is stored in R2 under the `files/{id}` key. File metadata (original name, content type, size, upload/expiry timestamps) is kept in R2 **custom metadata**, so listing never has to read object bodies.

A scheduled trigger (`export default { scheduled: ... }`) periodically scans R2 and deletes any objects whose `expiresAt` timestamp has passed. When a file is downloaded/HEADed past its expiry, it is also lazily deleted on the spot.

---

## Requirements

- Node.js 18+ (only needed for local dev / wrangler)
- A free [Cloudflare account](https://dash.cloudflare.com)
- A Cloudflare **R2 bucket** and **Workers** enabled

---

## Deployment

### 1. Create the R2 bucket

```bash
npx wrangler r2 bucket create <your-bucket-name>
```

The Worker uses a **binding name** of `BUCKET` (see [Configuration](#configuration)).

### 2. Add the files

From this repo:

```
worker.js
wrangler.toml
```

### 3. Configure

Copy the template and fill in your values:

```bash
cp wrangler.toml.example wrangler.toml
```

Set the R2 binding and the scheduled cron trigger, then create the secret:

```bash
# generate a strong API key
openssl rand -hex 32

# store it as a Worker secret (recommended — keeps it out of your code)
npx wrangler secret put API_KEY
```

### 4. Deploy

```bash
npx wrangler deploy
```

Once deployed, your Worker runs at `https://<your-worker>.workers.dev`.

---

## Configuration

All configuration is **environment-based** — there are no hardcoded secrets in the source.

| Binding / Secret | Type          | Required | Description                                  |
| ---------------- | ------------- | -------- | -------------------------------------------- |
| `BUCKET`         | R2 binding    | ✅ Yes    | The R2 object binding for file storage       |
| `API_KEY`        | Secret        | ✅ Yes    | The bearer token / password protecting the API |

> ⚠️ **Security:** Never commit a real `API_KEY` to the repository. Always use `wrangler secret put API_KEY` (or set it in the dashboard). Environment variables are not read from `wrangler.toml` in production.

### `wrangler.toml` (example)

```toml
name = "r2-storage"
main = "worker.js"
compatibility_date = "2024-11-01"

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "my-files-bucket"

[triggers]
crons = ["0 */6 * * *"]   # run expired-file cleanup every 6 hours
```

**Note:** `expires` on files is a *soft* TTL. Expired files are removed either lazily (on access) or when the cron cleanup runs. Configure the cron frequency to match how aggressively you want expired data purged.

---

## API Reference

**Base URL:** `https://<your-worker>.workers.dev`

**Authentication:** All `/api/*` endpoints require the API key via one of:

```
Authorization: Bearer YOUR_API_KEY
```

...or an existing session cookie (set by `POST /auth/login`).

**Allowed expiration values:** `1h`, `6h`, `12h`, `1d`, `3d`, `7d`, `30d`, `90d`, `never`

---

### Health check

```http
GET /api/health
```

Returns service status, version, and the configured bucket.

```bash
curl "https://<worker>.workers.dev/api/health"
```

---

### Upload a file (raw / streaming)

```http
PUT /api/upload?filename=photo.jpg&expires=7d
Content-Type: image/jpeg
Authorization: Bearer YOUR_API_KEY
```

`filename` may also be supplied via the `X-Filename` header. The raw request body is streamed straight to R2.

```bash
# single-part body
curl -X PUT "https://<worker>.workers.dev/api/upload?filename=photo.jpg" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  --data-binary @photo.jpg
```

**Response `201 Created`:**

```json
{
  "object": "file",
  "status": "complete",
  "id": "a1b2c3...",
  "key": "files/a1b2c3...",
  "name": "photo.jpg",
  "size": 123456,
  "content_type": "image/jpeg",
  "uploaded_at": "2026-08-16T10:00:00Z",
  "expires_at": "2026-08-23T10:00:00Z",
  "download_url": "https://<worker>.workers.dev/api/files/a1b2c3..."
}
```

---

### Upload a file (multipart)

```http
POST /api/upload?expires=7d
Content-Type: multipart/form-data
Authorization: Bearer YOUR_API_KEY
```

```bash
curl -X POST "https://<worker>.workers.dev/api/upload" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@photo.jpg" \
  -F "expires=7d"
```

Requires a `file` field (`expires` optional — default `7d`).

---

### List files

```http
GET /api/files?limit=100&cursor=...&search=cat&type=image&sort=size&order=desc
Authorization: Bearer YOUR_API_KEY
```

| Query param | Default | Description                                       |
| ----------- | ------- | ------------------------------------------------- |
| `limit`     | `100`   | Results per page (1–1000)                         |
| `cursor`    | —       | Pagination cursor from the previous response      |
| `search`    | —       | Case-insensitive substring match on filename      |
| `type`      | —       | Case-insensitive substring match on MIME type     |
| `sort`      | `uploaded` | `uploaded`, `name`, or `size`                  |
| `order`     | `desc`  | `asc` or `desc`                                   |

**Response `200 OK`:**

```json
{
  "object": "list",
  "data": [
    {
      "id": "a1b2c3",
      "key": "files/a1b2c3",
      "name": "photo.jpg",
      "size": 123456,
      "content_type": "image/jpeg",
      "uploaded_at": "2026-08-16T10:00:00Z",
      "expires_at": null,
      "etag": "...",
      "download_url": "/api/files/a1b2c3"
    }
  ],
  "pagination": { "cursor": null, "has_more": false },
  "count": 1
}
```

---

### Download a file

```http
GET /api/files/<id>
# force download (attachment):
GET /api/files/<id>?download=1
Authorization: Bearer YOUR_API_KEY
```

Supports HTTP `Range` headers (`206 Partial Content`):

```bash
curl "https://<worker>.workers.dev/api/files/a1b2c3" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Range: bytes=0-1023"
```

Returns `404` if not found, `410` if expired (and deletes it).

---

### Get file metadata (HEAD)

```http
HEAD /api/files/<id>
Authorization: Bearer YOUR_API_KEY
```

Returns headers only (`Content-Type`, `Content-Length`, `ETag`, `Accept-Ranges`). `404` / `410` statuses apply as above.

---

### Delete a file

```http
DELETE /api/files/<id>
Authorization: Bearer YOUR_API_KEY
```

---

### Bulk delete

```http
DELETE /api/files
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{ "ids": ["a1b2c3", "d4e5f6"] }
```

Up to 1000 IDs per request.

---

### Storage statistics

```http
GET /api/stats
Authorization: Bearer YOUR_API_KEY
```

Returns total file count, total bytes, and expired count.

---

### Browser session

```http
POST /auth/login
Content-Type: application/json

{ "token": "YOUR_API_KEY" }
```

Sets an HttpOnly, Secure, `SameSite=Strict` session cookie (`Max-Age: 7d`). Plain-text bodies are also accepted. Use to access the `/dashboard` UI in a browser.

```http
POST /auth/logout
```

Clears the session cookie.

---

## Local development

```bash
# install wrangler
npm install -g wrangler

# set up local R2 + secrets
mkdir -p .dev.vars
echo "API_KEY=dev-secret-key" > .dev.vars

# run the Worker locally (requires local R2 or Miniflare)
npx wrangler dev
```

`wrangler dev` serves `http://localhost:8787`.

---

## Security notes

- **Never persist your real `API_KEY` in repo files** — use `wrangler secret put API_KEY`.
- Authentication uses **constant-time comparison** (`safeEqual`) to reduce timing-attack exposure.
- The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
- Response headers include security hardening (`nosniff`, frame/iframe and referrer policies, restricted permissions policy).
- Filenames are **sanitized** and served via an explicit `Content-Disposition` to reduce header-injection / XSS risk.
- CORS is wide-open (`*`) for API calls by design; restrict it if you run this for a closed audience.

---

## License

[MIT](./LICENSE)

---

## Disclaimer

This project is provided as-is for public reference. It depends on Cloudflare R2/Workers billing; you are responsible for the data you store and for configuring auth, CORS, and cron policies appropriate to your deployment.