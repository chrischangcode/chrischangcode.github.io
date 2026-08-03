# AKS security-advisory site

This directory is published verbatim to
**<https://chrischangcode.github.io/aks-security-advisory/>**. It is split into a
small static **hub** at the root and one sub-directory per advisory set (see
[issue #40](https://github.com/chrischangcode/aks-security-advisory/issues/40)):

```
site/
  index.html        Static hub / chooser. Explains the site and links to each
                    advisory set. Also carries the legacy-hash redirect shim
                    (old /#/<route> links -> /vhd/#/<route>). No JS needed for
                    its own content.
  llms.txt          Machine-readable entry point for AI agents (feed shapes).
  robots.txt        Permissive (allow all).
  shared/
    styles.css      Azure light theme shared by the hub and every app.
  vhd/              The VHD (node image) advisory SPA (live).
    index.html      Page shell + header nav.
    app.js          The whole front-end (see below).
  README.md         This file.
```

Only `vhd/` is live today; a container-image advisory is planned under a sibling
directory. Everything below describes the **VHD app** in `vhd/`.

A zero-build static front-end for browsing the AKS VHD security-advisory feed
(the per-CVE JSON + `index.json` artifact produced by `aks-cve feed`). It offers
live search by CVE id and filtering by OS/SKU lineage, headline status, and
severity (the advisory list is paged at 1,000 rows so a large feed never renders
one giant table; changing any filter jumps back to the first page), a detail
view per CVE, an **Installed paths** page that maps a
scanner-reported path (e.g. `/usr/bin/curl`) to the owning package(s), an
**Extended binaries** page that lists AKS-laid binaries and how each is covered,
and a help/glossary page.

> **Community project.** This site and the feed behind it are an independent,
> open-source effort. They are **not** an official Microsoft/Azure product and
> are not an authoritative source of truth for AKS security posture.

## What it is

- Plain **HTML + CSS + vanilla JS** — no framework, no bundler, no build step.
  Just static files served over HTTP.
- `vhd/index.html` — page shell + header nav (Advisories / Installed paths / Extended binaries / Help).
- `shared/styles.css` — Azure light theme (white surfaces, `#0078d4` accent);
  shared by the hub and the app.
- `vhd/app.js` — the whole front-end: data loading, search/filter, detail view,
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
- `pathmap/index.json` + `pathmap/<key>.json` — the installed-path → package
  maps behind the **Installed paths** page and the advisory ↔ path cross-links
  (best-effort; the page degrades gracefully if the feed omits them). See
  [docs/ADVISORY-SCHEMA.md](../docs/ADVISORY-SCHEMA.md#installed-path--package-supplemental-feed-pathmap).
- `components.json` — per-OS-family classification of the extended binaries
  behind the **Extended binaries** page (best-effort; the page is hidden if the
  feed omits it). See
  [docs/ADVISORY-SCHEMA.md](../docs/ADVISORY-SCHEMA.md#extended-binary-coverage-manifest-componentsjson).

> **Coverage limitation — no container-image scanning yet.** The `covered_by_scan`
> coverage shown on the **Extended binaries** page comes from a binary (Trivy)
> scan of downloadable binary **archives (tarballs) only**. Extended components
> distributed as container/OCI **images** — notably `kubernetes-binaries`
> (`kubelet` / `kubectl`) and `azure-acr-credential-provider` — are **not**
> scanned and appear as `aks_built` / `scan_pending` instead. Adding image
> scanning is tracked in the feed repo's issue #8.

### Where it looks for the data

`vhd/app.js` resolves the feed base at load time. Because the app lives one
level deep in `vhd/`, the probe paths are relative to `vhd/`:

1. `?data=<url>` query-string override, if present; else
2. `../data` (the deployed GitHub Pages site — the feed is copied to
   `/aks-security-advisory/data/`, i.e. one level up from `vhd/`); else
3. `../../feed-out` (local preview from a repo checkout — the repo-root
   `feed-out/`, two levels up from `site/vhd/`).

## Local preview

Serve the **repository root** (so `site/`, its sub-directories, and `feed-out/`
are all reachable) and open the app path:

```bash
# from the repo root, after building a feed into ./feed-out
python3 -m http.server 8799
# then open the hub:     http://localhost:8799/site/
# or the VHD app direct: http://localhost:8799/site/vhd/
```

The hub (`/site/`) is plain static HTML; the VHD app lives at `/site/vhd/` and
falls back to `../../feed-out` (the repo-root `feed-out/`) when `../data` is
absent. Legacy `#/<route>` links opened on the hub are forwarded into `vhd/`.

If you don't have a `feed-out/` yet, build one first:

```bash
aks-cve feed --lineage azurelinux:gen2:3.0containerd --out ./feed-out
```

You can also point the app at any feed without moving files:

```
http://localhost:8799/site/vhd/?data=/feed-out
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
