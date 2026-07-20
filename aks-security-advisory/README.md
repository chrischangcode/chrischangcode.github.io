# AKS VHD security-advisory site

A zero-build static front-end for browsing the AKS VHD security-advisory feed
(the per-CVE JSON + `index.json` artifact produced by `aks-cve feed`). It offers
live search by CVE id and filtering by OS/SKU lineage, headline status, and
severity, plus a detail view per CVE and a help/glossary page.

> **Community project.** This site and the feed behind it are an independent,
> open-source effort. They are **not** an official Microsoft/Azure product and
> are not an authoritative source of truth for AKS security posture.

## What it is

- Plain **HTML + CSS + vanilla JS** — no framework, no bundler, no build step.
  Just static files served over HTTP.
- `index.html` — page shell + header nav (Advisories / Help & glossary / Source).
- `styles.css` — Azure light theme (white surfaces, `#0078d4` accent).
- `app.js` — the whole front-end: data loading, search/filter, detail view,
  tooltips, and the help page. The `STATUS_HELP` / `FIELD_HELP` glossaries in
  `app.js` are the single source of truth for both the ⓘ tooltips and the help
  page, so the two never drift.

## Data contract

The site reads the feed produced by [`aks-cve feed`](../docs/CLI.md):

- `index.json` — the listing + facets. The site relies on the doc-level
  `releases` / `severities` / `statuses` facet lists and each entry's `releases`
  labels to drive its filter controls **without fetching every per-CVE file**.
  See [docs/ADVISORY-SCHEMA.md](../docs/ADVISORY-SCHEMA.md#index-indexjson).
- `advisories/<CVE>.json` — fetched lazily when a CVE detail view is opened.

### Where it looks for the data

`app.js` resolves the feed base at load time:

1. `?data=<url>` query-string override, if present; else
2. `data/` (used by the deployed GitHub Pages site — the feed is copied there); else
3. `../feed-out` (used for local preview from a repo checkout).

## Local preview

Serve the **repository root** (so both `site/` and `feed-out/` are reachable)
and open the site path:

```bash
# from the repo root, after building a feed into ./feed-out
python3 -m http.server 8799
# then open:  http://localhost:8799/site/
```

If you don't have a `feed-out/` yet, build one first:

```bash
aks-cve feed --lineage azurelinux:gen2:3.0containerd --out ./feed-out
```

You can also point the site at any feed without moving files:

```
http://localhost:8799/site/?data=/feed-out
```

## Deployment

Live at **<https://chrischangcode.github.io/aks-security-advisory/>**.

The [`pages`](../.github/workflows/pages.yml) workflow publishes this directory.
Because this repo is private (and Free-plan Pages only serves public repos), it
does not deploy Pages here — instead it downloads the `aks-vhd-advisory-feed`
artifact from the most recent successful
[`build-advisories`](../.github/workflows/build-advisories.yml) run, copies it to
`_site/data/`, and **pushes `_site` into the `aks-security-advisory/`
sub-directory of the public `chrischangcode.github.io` user site** (via a
write-scoped deploy key). Publishing never rebuilds the feed (and never adds
GitHub-API / OVAL rate-limit pressure). All asset references are relative, so the
site works unchanged under the `/aks-security-advisory/` sub-path.
