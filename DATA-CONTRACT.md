# AKS security-advisory feed — data contract

This document is the canonical, versioned description of the JSON published under
the [AKS security advisory site](https://chrischangcode.github.io/aks-security-advisory/).
The site is a zero-build static front-end; all data is plain JSON you can consume
directly from the `data/` directory. The internal tooling that produces the feed
is intentionally out of scope here — only the published shapes are contractual.

Schema version: **1.0** (see `schema_version` on every document).

## Endpoints

All paths are relative to the site root, e.g.
`https://chrischangcode.github.io/aks-security-advisory/data/index.json`.

| Path | Purpose |
| --- | --- |
| `data/index.json` | One summary row per advisory + global filter facets. |
| `data/advisories/<CVE>.json` | Full per-CVE advisory. |
| `data/pathmap/index.json` | Directory of installed-path → package maps. |
| `data/pathmap/<key>.json` | One deduplicated path → package map for an OS release. |

## `data/index.json`

```json
{
  "schema_version": "1.0",
  "generated": "<ISO-8601 UTC>",
  "count": 2543,
  "releases": ["AKSAzureLinuxV3/gen2", "..."],
  "statuses": ["fixed", "fix_available_upstream", "..."],
  "severities": ["Critical", "High", "Medium", "Low"],
  "advisories": [
    {
      "id": "CVE-2025-12345",
      "headline_status": "fixed",
      "severity": "High",
      "updated": "<ISO-8601 UTC>",
      "releases": ["AKSAzureLinuxV3/gen2", "..."],
      "packages": ["openssl", "..."],
      "summary": "<optional short text>"
    }
  ]
}
```

`releases`, `statuses`, and `severities` at the document level are sorted facet
lists so the site can build its filter controls from `index.json` alone. Each
`advisories[]` entry repeats the `releases` and `packages` that appear in that
advisory so the list can be filtered without loading every advisory document.

## `data/advisories/<CVE>.json`

```json
{
  "schema_version": "1.0",
  "id": "CVE-2025-12345",
  "severity": "High",
  "headline_status": "fixed",
  "updated": "<ISO-8601 UTC>",
  "description": "<optional>",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-12345", "..."],
  "packages": [
    {
      "package": "openssl",
      "release": "AKSAzureLinuxV3/gen2",
      "status": "fixed",
      "severity": "High",
      "advisory_id": "<optional distro advisory id>",
      "fixed_version": "<optional>",
      "upstream_fixed_version": "<optional>",
      "first_fixed_build": "<optional VHD build>",
      "latest_build": "<optional VHD build>",
      "justification": "<optional VEX justification>",
      "statement": "<optional VEX statement>",
      "evidence": { "<label>": "<url>" }
    }
  ],
  "additive": {
    "coverage": "covered_by_package",
    "source": "component-upstream",
    "note": "<human-readable explanation of the coverage>",
    "items": [
      { "name": "containerd", "coverage": "covered_by_package",
        "version": "2.2.4-4.azl3", "package": "containerd2" }
    ]
  }
}
```

### `references`

External, human-readable links for the CVE:

- **NVD** — `https://nvd.nist.gov/vuln/detail/<CVE>`.
- **Ubuntu CVE Tracker** — `https://ubuntu.com/security/<CVE>` (Ubuntu advisories).
- **Azure Linux (Astrolabe)** — the per-CVE status page for Azure Linux
  advisories. Astrolabe is served from an Azure Static Web App whose hostname is
  not stable, so the feed resolves `https://aka.ms/astrolabe` at build time and
  appends the client-side route `/#/cve/<CVE>`.
- The advisory-feed source(s) the row was derived from.

### `additive`

The **additive surface** is the set of binaries and container images laid on top
of the base OS image (e.g. `kubelet`, `containerd`, CNI plugins, `oras`) rather
than installed as base-OS packages. The `additive` object summarises how much of
that surface this feed can assess for the CVE:

```json
"additive": {
  "coverage": "covered_by_package",
  "source": "component-upstream",
  "note": "<human-readable explanation of the coverage posture>",
  "items": [
    { "name": "containerd", "coverage": "covered_by_package",
      "version": "2.2.4-4.azl3", "package": "containerd2" }
  ]
}
```

- **`coverage`** (section level) — `covered_by_package` when at least one item is
  assessed (maps to a tracked distro package, or was assessed by a binary scan);
  otherwise `not_assessed`.
- **`source`** — provenance tag for the section; currently always
  `component-upstream`.
- **`note`** — a human-readable sentence explaining the coverage posture.
- **`items[]`** — the extended binaries relevant to *this* CVE. Each item carries:
  - **`name`** — the binary / component name.
  - **`coverage`** — the per-item posture (see table below); this is the
    authoritative statement for that binary.
  - **`version`** — the version baked into the node image (optional).
  - **`package`** — for `covered_by_package` items, the installed distro package
    whose rows in *this same advisory* assess the binary (use it to cross-link).
  - **`note`** — optional per-item explanation.

Only items relevant to this CVE are attached here. A full per-build inventory of
every extended binary (including ones that never appear in any CVE) is published
separately and backs the site's *Extended binaries* page.

#### Additive coverage vocabulary (`items[].coverage`)

| coverage | meaning |
| --- | --- |
| `covered_by_package` | The binary is the **same artifact** as an installed distro package the base distro advisory feed tracks (e.g. the `containerd` binary is the `containerd2` package on Azure Linux). Its CVE status **is** assessed — the item carries `package`, and that package's rows appear in this advisory. |
| `covered_by_scan` | Assessed by an **independent binary scan** of the extended binary itself, because the distro feeds don't track it. The relevant package rows carry scan-derived `evidence` (the scanned artifact and the scanner reference) instead of a distro advisory id. |
| `scan_pending` | Installed as a distro package but **absent from the base distro's advisory feed** — typically a Microsoft-repackaged build (e.g. `moby-containerd` on Ubuntu). Status is not asserted and it is **never** treated as covered. Carries `package`. |
| `aks_built` | Built by AKS or downloaded from upstream and never distro-packaged (`kubelet`, `kubectl`, `oras`, Azure CNI, ...). No distro feed tracks it, so no fix status is asserted. |
| `not_baked` | A distro package installed only conditionally (e.g. GPU drivers) and absent from the mainstream baked image for this lineage — nothing to assess here. |
| `not_assessed` | Section-level fallback when no item is assessed. |

Items with `scan_pending`, `aks_built`, `not_baked`, or `not_assessed` coverage
are **never** represented as base-OS CVEs and carry no assured fix status.

### Status vocabulary (`status` / `headline_status`)

Ordered from most to least severe headline precedence:

| Status | Meaning |
| --- | --- |
| `affected` | Vulnerable; no upstream fix available yet. |
| `fix_available_upstream` | Distro shipped a fixed version, but no AKS VHD build carries it yet. |
| `will_not_fix` | Distro will not fix (e.g. Ubuntu `ignored`, "changes too intrusive"). |
| `fixed` | A shipped AKS VHD build carries the fix (`first_fixed_build`). |
| `not_affected` | Not affected (VEX `not_affected`, usually with a `justification`). |
| `under_investigation` | Triage in progress. |

`headline_status` is the single most relevant status across all `packages[]` rows
for the CVE.

## `data/pathmap/index.json`

Maps a scanner-reported installed path (e.g. `/usr/bin/curl`) back to the owning
package name(s) used in advisories, per OS release.

```json
{
  "schema_version": "1.0",
  "generated": "<ISO-8601 UTC>",
  "default_lineage": "AKSAzureLinuxV3/gen2",
  "lineages": { "AKSAzureLinuxV3/gen2": "azurelinux-3.0", "AKSUbuntu-2404/gen2": "ubuntu-noble" },
  "maps": ["azurelinux-3.0", "ubuntu-noble", "..."]
}
```

`lineages` maps a site OS/SKU label to the map `key`; `default_lineage` is the
map the paths page selects first (the latest normal VHD of the most mainstream
OS/SKU). Only lineages whose map built successfully are advertised.

## `data/pathmap/<key>.json`

```json
{
  "schema_version": "1.0",
  "type": "pathmap",
  "key": "azurelinux-3.0",
  "os_family": "azurelinux",
  "release": "3.0",
  "path_count": 13711,
  "package_count": 2075,
  "by_path": { "/usr/bin/curl": ["curl"], "...": ["..."] }
}
```

A single deduplicated map is shared by every SKU of the same OS family + release.
`by_path` values are arrays because a path/basename can be owned by more than one
package; the installed one is disambiguated against a build's package set. Per-key
documents use compact JSON to keep transfer size down.
