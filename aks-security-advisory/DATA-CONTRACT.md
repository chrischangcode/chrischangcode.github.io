# Data contract -- AKS Security Advisories (VHD feed)

This document is the stability contract for the machine-readable feed published
under `data/` at
`https://chrischangcode.github.io/aks-security-advisory/data/`. It states what a
consumer (human or agent) may rely on, what may change without notice, and how
changes are signalled.

It deliberately does **not** hand-list endpoints, byte sizes or counts. Those
are volatile and are published, build-consistent, in the feed itself:

- `data/manifest.json` -- the authoritative inventory of every endpoint, its
  byte size, its `schema_version`, and whether it is `optional`. If this
  contract and the manifest ever disagree about whether an endpoint exists or is
  optional, **the manifest wins**.
- `data/glossary.json` -- the controlled vocabularies (status, coverage, field
  help) with per-value counts measured from the current build.
- `data/llms.txt` -- a generated agent entrypoint carrying the live endpoint
  sizes, the current release-label set, and a build-verified worked example.

## Versioning

- **Document schema.** Each feed document declares a `schema_version`, and
  `data/manifest.json` records the `schema_version` of every endpoint. Within a
  major version, changes are additive only: new fields may appear; existing
  fields keep their meaning. A breaking change bumps the major version, and the
  old and new versions are distinguishable by that field.
- **Manifest schema.** `data/manifest.json` itself declares a top-level
  `schema_version` and a `type` of `aks-vhd-feed-manifest`.
- **Discovering existence.** An endpoint is present iff it appears in
  `data/manifest.json` with `optional: false`, or it appears with
  `optional: true` and returns 200. Treat a 404 on an `optional` endpoint (or a
  404 on `manifest.json` itself, from a feed that predates it) as "absent", not
  as an error -- fall back to the base endpoints (`index.json`,
  `advisories/<ID>.json`).

## What you MAY rely on

- **Base endpoints exist.** `data/index.json` (full advisory listing) and
  `data/advisories/<CVE>.json` (one document per advisory) are non-optional.
- **Every advisory has an HTML twin.** `data/advisory-pages/<CVE>.html` renders
  the same record as `data/advisories/<CVE>.json` and needs no JavaScript, so a
  pasted URL returns the advisory rather than an empty shell. The JSON remains
  authoritative; the page is a representation of it, never a second source of
  truth. The collection is optional -- check `manifest.json` before relying on
  it, and fall back to the JSON, which is not optional.
- **Identifiers are stable keys.** A `<CVE>` id maps to
  `data/advisories/<CVE>.json` and `data/advisory-pages/<CVE>.html`. Do not
  construct any other filename yourself:
  resolve package and pathmap filenames through the relevant
  `index.json` (`by-package/index.json`, `pathmap/index.json`), which may map a
  logical name to a different or aliased file.
- **The controlled vocabularies are closed sets.** `status` and `coverage`
  values come only from `data/glossary.json`. New values may be *added* across
  versions; existing ones are not silently repurposed.
- **`headline_status` is cross-lineage, not per-SKU.** It is the single
  most-actionable status across all lineages. For a SKU-level answer, read the
  `packages[]` row in `data/advisories/<CVE>.json` whose `releases[]` contains
  your lineage label (one row covers every lineage sharing that assessment, so
  match by membership, not equality). `status.counts` in the glossary is headline-derived; its
  `counts_basis` field says so.
- **A miss is "unknown", never "not vulnerable".** If a path, package, or
  (CVE, lineage) pair resolves to nothing, that is unknown / not-assessed. The
  pathmap indexes only `/bin` and `/sbin` executables (`indexed_prefixes`); a
  path outside that scope is out of scope, not clean.
- **Install paths are per-family.** Each VHD lineage has its own pathmap under
  `data/pathmap/`; resolve a binary path within your lineage, never against a
  merged map.

## What MAY change without notice

- **Endpoint byte sizes and per-value counts.** They change on every rebuild.
  Never hardcode them; read `data/manifest.json` / `data/glossary.json`.
- **The set of advisories, packages and release labels.** New CVEs, packages and
  VHD lineages appear as the feed evolves. Enumerate them from the feed, do not
  assume a fixed set.
- **Optional endpoints.** Endpoints marked `optional: true` in the manifest
  (e.g. query slices, the manifest itself on older feeds) may be absent. Always
  have a base-endpoint fallback.
- **Human-facing HTML.** The pages under `vhd/` are a client-rendered SPA; their
  markup is not a contract. Read the JSON feed, not the rendered HTML.

## Not in scope

This feed covers **AKS VHD (node image) base packages** only. It is a community
project, not an official Microsoft/Azure product, and not an authoritative
source of truth for AKS security posture. A container-image advisory feed is
planned (issue #40) but not published here today.
