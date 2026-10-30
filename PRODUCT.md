# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing codebase answers this: a single Cloudflare Worker (`worker.js`) with no build
step. Every page is an inline HTML template literal returned from the Worker. Styling is
plain CSS or a CDN Tailwind script tag; there is no bundler, no npm dependency, and no
separate asset pipeline. Any redesign must ship as self-contained HTML/CSS/JS strings
inside `worker.js`, and must not introduce a build step, a framework, or a runtime
dependency the Worker cannot serve.

## Users

Two audiences, distinct in situation and stakes:

1. **The owner-operator** — a developer running their own file host. They arrive from a
   terminal or a bookmarked tab, authenticated with an API key, and want to see what is
   stored, how much space it takes, when things expire, and to delete or fetch a file.
2. **The person who just needs to send a file** — no account, no interest in the API.
   They open the home page, drop a file, and want a link they can paste into a chat
   within seconds. Seven days later the file is gone and they never come back.

## Product Purpose

A private file store and a public drop-box in the same Worker, backed by Cloudflare R2.
One upload yields one URL that opens in a browser or streams to a client. Success is a
file sent without an account and without a build step, and an owner who can see and
control everything in it.

## Positioning

Storage that is one HTTP call, not a platform. There is no SDK, no client library, no
account system, and no vendor surface between the caller and the bytes: `curl -X PUT`
is the whole integration. The public uploader carries no key at all, so the same
deployment is both a private API and an anonymous drop box — a combination the
category's products usually split into two services.

## Operating Context

- Uploading: raw `PUT` with a streaming body, or `multipart/form-data` with `file` and
  `expires` fields. Public uploads are capped at 100 MB and always expire in 7 days.
- Expiration: `1h, 6h, 12h, 1d, 3d, 7d, 30d, 90d, never`. Soft TTL, swept by a cron
  trigger and lazily on access.
- Retrieval: full download or HTTP range requests; `?download=1` to force an attachment.
- Public links live under `/f/:id` and serve a preview page to browsers, bytes to
  clients that do not ask for HTML.
- The owner's surfaces are `/dashboard` (files, stats, upload, bulk delete, per-file
  metadata) and `/docs` (the endpoint reference).
- Real deployments are known by their own hostname; the live instance used for review is
  `cdn.nullstacks.workers.dev`.

## Capabilities and Constraints

Confirmed functionality: streaming upload; multipart upload; per-file expiry; listing
with search, MIME-type filter, sort and cursor pagination; HEAD metadata; range
downloads; single and bulk delete (1000 per call); storage statistics; scheduled
expiration sweep; bearer-token and session-cookie auth with constant-time comparison;
sanitized filenames and forced `Content-Disposition`; security headers; open CORS.

Technical constraints: one file, no build step, no client dependencies beyond what a CDN
can serve; all markup is generated as strings; the dashboard is a single page with
vanilla JS; the reference deployment has no separate asset host.

## Brand Commitments

None binding. The product has carried the name **Content Delivery** across two prior
visual worlds and the user has asked for a full redesign, so the name, the three
surfaces (home, docs, dashboard), and the public-link behaviour are preserved; the
visual identity is not.

## Evidence on Hand

No testimonials, customer logos, benchmarks, press, or usage statistics exist and none
may be invented. The only evidence available is the product's own behaviour, its real
endpoints, real response shapes, real limits (100 MB public, 7-day public expiry,
1000-object bulk delete, listed expiry values), and the live deployment URL.

## Product Principles

- The first screen must let a stranger send a file. No account, no explanation first.
- Show the mechanism. This is an API product; the request is the product, so real
  endpoints and real responses belong in the interface, not paraphrased.
- Never imply more than the system does. No invented metrics, no implied teams, no
  fake activity.
- Expiry is a feature, not a warning: files disappear on purpose.
- The private API and the public drop box are one system and should read as one system.
