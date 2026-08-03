/*
 * AKS VHD Security Advisories — static front-end.
 *
 * Zero build step, zero dependencies. It reads the JSON feed produced by
 * `aks-cve feed` (aksadvisory.feed): a small `index.json` (one compact entry
 * per CVE, plus `releases`/`severities`/`statuses` facets) and, on demand, the
 * per-CVE `advisories/<CVE>.json` files.
 *
 * Data location: see `candidateDataBases()`. This app lives in `site/vhd/`, one
 * level below where the feed is deployed. On GitHub Pages the workflow places
 * the feed at `/aks-security-advisory/data/`, i.e. `../data` relative to this
 * app; for local preview (`python -m http.server` from the repo root, open
 * `/site/vhd/`) it transparently falls back to `../../feed-out` (the repo-root
 * `feed-out/`). A `?data=<base>` query override wins over both.
 */
"use strict";

/* ---------- glossary (single source of truth for tooltips + help page) ---------- */
//
// These objects are the BAKED-IN FALLBACK. The canonical vocabulary lives in
// Python (aksadvisory/feed/vocab.py) and is emitted as `data/glossary.json` with
// per-value counts measured from the build. `loadGlossary()` prefers that
// document, replacing these defaults section-by-section (see `applyGlossary`);
// when it is absent (the site can be served against an older feed artifact that
// predates glossary.json) these baked-in copies keep every tooltip and the help
// page working. They MUST stay identical to vocab.py -- tests/test_vocab.py
// fails if they drift. They are `let`, not `const`, so the generated glossary
// can override them at runtime.

// Per-status explanation. Reused by badge tooltips and the help page so the two
// never drift.
let STATUS_HELP = {
  fixed: "A scanned AKS VHD build ships a package version at or above the distro's fixed version. The 'first fixed build' field names the earliest build that carries the fix.",
  fix_available_upstream: "The distro (Azure Linux / Ubuntu) has published a fixed package, but none of the scanned VHD builds ship it yet. The fix exists upstream and is expected in a future node image.",
  affected: "Vulnerable, with no upstream fix available yet. Surfaced only where a vendor VEX / Ubuntu CVE Tracker asserts it, since a fixless CVE cannot be enumerated from OVAL alone. The generated glossary records how large a share of the feed it actually is.",
  not_affected: "Excluded by a vendor verdict — an Azure Linux CSAF/VEX justification or an Ubuntu CVE Tracker 'not-affected' (e.g. the vulnerable code path is not present/reachable). The justification is shown on the advisory.",
  under_investigation: "Triage is not complete — either no distro OVAL/VEX verdict exists yet, or the Ubuntu CVE Tracker marks the package 'needs-triage'.",
  will_not_fix: "The vendor will not ship a fix (Ubuntu CVE Tracker 'ignored' — e.g. the release is past standard support, or the fix is deemed too intrusive). The reason is shown on the advisory.",
};

let STATUS_LABELS = {
  fixed: "Fixed",
  fix_available_upstream: "Fix available upstream",
  affected: "Affected",
  not_affected: "Not affected",
  under_investigation: "Under investigation",
  will_not_fix: "Will not fix",
};

// Coverage vocabulary for extended binaries (release-notes components).
let COVERAGE_LABELS = {
  covered_by_package: "Covered by package",
  covered_by_scan: "Covered by scan",
  scan_pending: "Scan pending",
  aks_built: "AKS-built / upstream",
  container_image: "Container image",
  not_baked: "Not baked in",
  not_assessed: "Not assessed",
};

let COVERAGE_HELP = {
  covered_by_package: "This extended binary is the same artifact as an installed distro package that the distro advisory feed actually tracks, so its CVE status IS assessed \u2014 see the linked package's advisories.",
  covered_by_scan: "Assessed by a binary (Trivy) scan of the extended binary itself, because the distro advisory feeds don't track it. Carries scan evidence rather than a distro package row. Only downloadable binary archives are scanned \u2014 tarballs and .deb/.rpm packages \u2014 while components shipped as container/OCI images are classified 'container_image' and not scanned.",
  scan_pending: "Installed as a distro package (typically a Microsoft-repackaged one from packages.microsoft.com \u2014 e.g. moby-containerd, moby-runc, aznfs) that the base distro's advisory feed does NOT track. Its status is honestly unknown here; a binary scan is planned. Not treated as covered.",
  aks_built: "Built by AKS or downloaded from upstream as a downloadable archive/package (oras, Azure CNI, cni-plugins, acr-mirror). No distro package exists for it in the base feed, so distro OVAL/CVE feeds do not track it; it is scanned by the binary overlay where an archive is available.",
  container_image: "Built/distributed by AKS as an OCI container image rather than a downloadable archive (kubelet/kubectl via the kubernetes-node image, azure-acr-credential-provider). The binary scan overlay assesses downloadable archives, not images, so these are not scanned here and are tracked by their own upstream.",
  not_baked: "A distro package installed only conditionally (e.g. GPU drivers / DCGM at node provisioning) and absent from the mainstream baked image \u2014 nothing to assess for this lineage.",
  not_assessed: "Not tracked by the distro advisory feeds (e.g. cached container images).",
};

// Fallback text for the components "Assessed as / why not" column when a row
// has neither a linked distro package nor its own note. Keeps that cell
// meaningful for every coverage class instead of a bare em-dash.
let COVERAGE_WHY = {
  covered_by_scan: "Assessed by a binary scan; see its scan advisories.",
  scan_pending: "Microsoft-repackaged distro package the base feed doesn't track; binary scan planned.",
  container_image: "Assessed by its upstream container image, not this feed.",
  aks_built: "Tracked by its own upstream, not a distro advisory feed.",
  not_baked: "Not present in the mainstream baked image.",
  not_assessed: "Not tracked by the distro advisory feeds.",
};

// Field/column explanations. Keyed by a short id used across the list and the
// detail view.
let FIELD_HELP = {
  cve: "The CVE identifier. Click it to open the full advisory with per-OS/SKU package status and evidence links.",
  severity: "Severity as reported by the distro advisory feed (OVAL): Critical, High, Medium, or Low. Sorted Critical → Low.",
  status: "The single most-actionable status across all OS/SKU lineages for this CVE (the 'headline' status). Open the advisory to see each lineage individually.",
  release: "The AKS VHD lineage(s) — OS family + generation/SKU, e.g. 'AzureLinux-V3/gen2' — where this CVE was assessed. Use the OS/SKU filter to narrow the list.",
  updated: "When this advisory record was last regenerated by the feed builder (UTC date).",
  search: "Filter the list live by CVE id substring, e.g. type '2026-4' to match CVE-2026-4xxx.",
  package: "The base-OS package (as named in the distro OVAL feed) affected by this CVE, e.g. 'expat' or 'openssl'.",
  binary_packages: "When one advisory row stands in for a source package that installs several binaries (most visibly the kernel: one 'linux-azure' row for its many linux-headers-*/linux-modules-* binaries), these are the individual installed binary packages it rolls up. Each links to other advisories naming that binary.",
  fixed_version: "The distro package version that resolves the CVE, and which a shipping VHD build was confirmed to carry.",
  upstream_fixed_version: "The distro package version that resolves the CVE upstream. No scanned VHD build ships it yet.",
  first_fixed_build: "The earliest scanned AKS VHD build whose installed package reaches the fixed version. A 'security-patch:<version>' value means the fix landed via a security-patch delta rather than a full build.",
  latest_build: "The newest scanned AKS VHD build (still on a pre-fix package version) — the baseline the 'fix available upstream' verdict was measured against.",
  advisory_id: "The distro advisory identifier the fixed version came from (e.g. an Azure Linux OVAL advisory id).",
  evidence: "Verifiable source links backing the verdict: the AgentBaker release-notes file listing the exact installed versions, and the distro OVAL/advisory feed.",
  retained_vulnerable_version: "Some install-only packages (notably the kernel) keep older versions on disk after an update so the node can roll back. The node boots the highest version \u2014 the one carrying the fix \u2014 so the verdict is 'fixed'. This is an older version still present on disk that is below the fix. Whether a vulnerability scanner reports this CVE for the node depends on its methodology: one that evaluates the running/highest version treats the node as fixed, while one that inventories every installed package version may still flag the retained older version.",
  additive: "Extended binaries laid on top of the base image (kubelet, CNI, containerd/runc, oras) and cached container images. Some are the SAME artifact as an installed distro package the distro feed tracks (e.g. the containerd binary is the Azure Linux containerd2 package) and so ARE assessed \u2014 see 'covered_by_package' below. Others are Microsoft-repackaged and not in the base distro feed ('scan_pending'), or AKS-built/upstream ('aks_built'), tracked by their own upstreams, not the distro feeds.",
  components: "Every extended binary AKS lays on top of the base image, with whether the distro advisory feeds can assess it. 'covered_by_package' = the same artifact as a distro package the feed actually tracks (its CVE status is in the advisories); 'scan_pending' = installed as a Microsoft-repackaged distro package the base distro feed doesn't track (e.g. moby-containerd on Ubuntu) \u2014 a binary scan is planned; 'aks_built' = built by AKS or downloaded from upstream (kubelet, oras, Azure CNI), in no distro feed; 'not_baked' = distro packages installed only conditionally (e.g. GPU drivers), absent from the mainstream image.",
  references: "External references for this CVE — NVD, and the authoritative distro CVE status page: Ubuntu's CVE Tracker and, for Azure Linux, the MSRC Update Guide page. Also includes the advisory-feed source.",
  paths: "The absolute install paths this package owns on the node image. Only executables under /bin and /sbin are indexed — the paths a scanner typically reports.",
  path_lookup: "Type a path a scanner reported (e.g. /usr/bin/curl) or just a file name (e.g. curl). The lookup returns the owning package(s) for the selected OS/SKU, which you can click through to its advisories.",
  path_os: "The AKS VHD lineage the path→package map was built for. Executable-path ownership is stable within an OS release, so every SKU of a release shares one map; the default is the mainstream Azure Linux 3 gen2 image.",
  pkg_filter: "Show only advisories that name a package matching this text (substring, case-insensitive). Cleared by Reset.",
};

const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

// The advisory list is rendered a page at a time so a large feed (tens of
// thousands of CVEs) never builds one giant table. Only the current page's rows
// are put in the DOM; filters reset back to the first page.
const LIST_PAGE_SIZE = 1000;

// This app is served from `<root>/vhd/`, one level below the feed:
//
//   deployed (GitHub Pages)  <root>/data/     -> "../data"
//   local dev (server at repo root, open      -> "../../feed-out"
//             /site/vhd/)   <repo>/feed-out/
//
// Both are tried in order and the first that yields a document that actually
// *looks like* a feed index wins. `?data=<base>` overrides both. See
// `loadIndex()` for the resolution itself.
const DEPLOYED_DATA_BASE = "../data";
const LOCAL_DEV_DATA_BASE = "../../feed-out";

const state = {
  dataBase: DEPLOYED_DATA_BASE,
  index: null,      // parsed index.json
  entries: [],      // index.advisories
  filters: { q: "", release: "", status: "", severity: "", pkg: "" },
  page: 0,          // current advisory-list page (0-based)
  detailCache: new Map(),
  // Installed-path -> package supplemental feed (loaded lazily on first visit
  // to #/paths, or when an advisory cross-links into it).
  pathmap: { index: null, docs: new Map(), triedIndex: false },
  pathFilters: { os: "", q: "" },
  // Extended-binary coverage manifest (components.json), loaded lazily.
  components: { data: null, tried: false },
  componentFilters: { os: "", coverage: "" },
  // Generated vocabulary + per-value counts (glossary.json). Loaded once at
  // startup and merged over the baked-in STATUS_HELP/COVERAGE_HELP/FIELD_HELP
  // above; `data` also backs the live status distribution shown on the help
  // page. Absent on older feed artifacts, in which case the baked-in copies win.
  glossary: { data: null, tried: false },
};

const $app = () => document.getElementById("app");

/* ---------- data loading ---------- */

// GitHub Pages (and most static hosts) send ETag/Last-Modified but a short,
// non-configurable Cache-Control. `cache: "no-cache"` does NOT disable caching:
// it forces a conditional revalidation on every load, so an unchanged file comes
// back as a tiny 304 (cached copy reused) and a rebuilt feed is picked up as a
// fresh 200. Net effect: the site only re-downloads data that actually changed,
// instead of showing a stale browser copy.
const REVALIDATE = { cache: "no-cache" };

/* ---------- feed location ---------- */

// Bases are declared above `state` (they seed its default). Resolution below.
//
// Deliberately no separate HEAD pre-flight: the probe IS the real GET, so the
// deployed path costs one round trip instead of two and the app does not depend
// on the host supporting HEAD. A base is only accepted when it returns parseable
// JSON with an `advisories` array, so a host that answers 200 with an HTML
// fallback for missing files cannot be mistaken for a feed.

function candidateDataBases() {
  const override = new URLSearchParams(location.search).get("data");
  const strip = (b) => b.replace(/\/+$/, "");
  return override
    ? [strip(override)]
    : [DEPLOYED_DATA_BASE, LOCAL_DEV_DATA_BASE];
}

function looksLikeFeedIndex(doc) {
  return !!doc && typeof doc === "object" && Array.isArray(doc.advisories);
}

async function loadIndex() {
  const tried = [];
  for (const base of candidateDataBases()) {
    let r;
    try {
      r = await fetch(base + "/index.json", REVALIDATE);
    } catch (e) {
      tried.push(base + " (network error)");
      continue;
    }
    if (!r.ok) {
      tried.push(base + " (HTTP " + r.status + ")");
      continue;
    }
    let doc;
    try {
      doc = await r.json();
    } catch (_e) {
      tried.push(base + " (not JSON)");
      continue;
    }
    if (!looksLikeFeedIndex(doc)) {
      tried.push(base + " (no advisories[])");
      continue;
    }
    state.dataBase = base;
    state.index = doc;
    state.entries = doc.advisories;
    return;
  }
  throw new Error("no feed index found — tried " + tried.join("; "));
}

async function loadAdvisory(id) {
  if (state.detailCache.has(id)) return state.detailCache.get(id);
  const r = await fetch(state.dataBase + "/advisories/" + encodeURIComponent(id) + ".json", REVALIDATE);
  if (!r.ok) throw new Error(id + " HTTP " + r.status);
  const adv = await r.json();
  state.detailCache.set(id, adv);
  return adv;
}

// Installed-path -> package feed. The index lists the available per-OS-release
// maps; each map is fetched on demand. All calls are best-effort: an older feed
// that predates the pathmap feed simply has no pathmap/ directory (404), and the
// paths page degrades to an informative message rather than an error.
async function loadPathmapIndex() {
  if (state.pathmap.index || state.pathmap.triedIndex) return state.pathmap.index;
  state.pathmap.triedIndex = true;
  try {
    const r = await fetch(state.dataBase + "/pathmap/index.json", REVALIDATE);
    if (r.ok) state.pathmap.index = await r.json();
  } catch (_e) { /* leave null */ }
  return state.pathmap.index;
}

async function loadPathmapDoc(key) {
  if (state.pathmap.docs.has(key)) return state.pathmap.docs.get(key);
  const r = await fetch(state.dataBase + "/pathmap/" + encodeURIComponent(key) + ".json", REVALIDATE);
  if (!r.ok) throw new Error(key + " HTTP " + r.status);
  const doc = await r.json();
  state.pathmap.docs.set(key, doc);
  return doc;
}

// Extended-binary coverage manifest (components.json). Best-effort: a feed that
// predates it simply 404s and the page degrades to an informative message.
async function loadComponents() {
  if (state.components.data || state.components.tried) return state.components.data;
  state.components.tried = true;
  try {
    const r = await fetch(state.dataBase + "/components.json", REVALIDATE);
    if (r.ok) state.components.data = await r.json();
  } catch (_e) { /* leave null */ }
  return state.components.data;
}

// Apply a generated glossary document over the baked-in vocabulary. When a
// section is present and well-formed (a non-empty object) it REPLACES the baked
// copy wholesale rather than merging into it: the generated document is
// authoritative when available, so a key the feed no longer publishes must not
// survive from the stale baked copy (that would re-introduce the very drift this
// document exists to prevent). A missing or malformed section falls back to the
// baked copy in full, so a partial/garbled document can never blank a tooltip.
function applyGlossary(doc) {
  if (!doc || typeof doc !== "object") return;
  const st = doc.status || {};
  const cov = doc.coverage || {};
  const fld = doc.field || {};
  const pick = (o, baked) =>
    (o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length) ? o : baked;
  STATUS_LABELS = pick(st.labels, STATUS_LABELS);
  STATUS_HELP = pick(st.help, STATUS_HELP);
  COVERAGE_LABELS = pick(cov.labels, COVERAGE_LABELS);
  COVERAGE_HELP = pick(cov.help, COVERAGE_HELP);
  COVERAGE_WHY = pick(cov.why, COVERAGE_WHY);
  FIELD_HELP = pick(fld.help, FIELD_HELP);
}

// Generated vocabulary + per-value counts (glossary.json). Best-effort and
// non-fatal: an older feed artifact that predates it simply 404s (or fails to
// parse) and the baked-in STATUS_HELP/COVERAGE_HELP/FIELD_HELP keep the UI
// fully functional. When present it is preferred (see applyGlossary) and its
// measured counts drive the live status distribution on the help page, so the
// vocabulary can never drift from the data (issue #39, F8).
async function loadGlossary() {
  if (state.glossary.tried) return state.glossary.data;
  state.glossary.tried = true;
  try {
    // Time-box the fetch: loadGlossary is deliberately off the first-render path
    // (see main), but a stalled connection (accepted, no body) must never be able
    // to hold up a re-render either. AbortSignal.timeout is guarded for older
    // browsers, which simply get an untimed best-effort fetch.
    const opts = { cache: "no-cache" };
    if (typeof AbortSignal !== "undefined" && AbortSignal.timeout) {
      opts.signal = AbortSignal.timeout(6000);
    }
    const r = await fetch(state.dataBase + "/glossary.json", opts);
    if (r.ok) {
      const doc = await r.json();
      if (doc && typeof doc === "object") {
        state.glossary.data = doc;
        applyGlossary(doc);
      }
    }
  } catch (_e) { /* leave baked-in vocabulary in place */ }
  return state.glossary.data;
}

// Resolve a lineage label (e.g. "AKSAzureLinuxV3/gen2") to its map key via the
// pathmap index, falling back to the index default when the label has no map.
function pathmapKeyForLabel(label) {
  const idx = state.pathmap.index;
  if (!idx) return null;
  if (label && idx.lineages && idx.lineages[label]) return idx.lineages[label];
  const def = idx.default_lineage;
  return (def && idx.lineages && idx.lineages[def]) || null;
}

/* ---------- dom helpers ---------- */

function el(tag, attrs, children) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "html") n.innerHTML = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
  }
  for (const c of [].concat(children || [])) {
    if (c == null) continue;
    n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return n;
}

// An accessible info affordance: shows `text` on hover (CSS bubble via data-tip),
// on keyboard focus (tabindex), and to screen readers / native title.
function info(text) {
  return el("span", {
    class: "info", tabindex: "0", role: "note",
    "data-tip": text, "aria-label": text, title: text,
  }, "\u24D8"); // ⓘ
}

// A label followed by its info icon (for table headers / detail field labels).
function labelWithInfo(text, helpKey) {
  const help = FIELD_HELP[helpKey];
  return el("span", { class: "hlabel" }, [text, help ? info(help) : null]);
}

function statusBadge(status) {
  return el("span", {
    class: "badge st-" + status,
    title: (STATUS_LABELS[status] || status) + " — " + (STATUS_HELP[status] || ""),
  }, STATUS_LABELS[status] || status || "\u2014");
}

function severityCell(sev) {
  return el("span", {
    class: "sev sev-" + (sev || ""),
    title: sev ? "Severity: " + sev : null,
  }, sev || "\u2014");
}

function isExternal(url) { return /^https?:\/\//i.test(url || ""); }

/* ---------- list view ---------- */

// Newest CVE first. CVE ids look like `CVE-<year>-<seq>`; the sequence is NOT
// zero-padded, so a plain string sort mis-orders (e.g. "...-9" > "...-1234").
// Compare year then sequence numerically, both descending.
function compareCveDesc(a, b) {
  const pa = /^CVE-(\d+)-(\d+)$/i.exec(a.id);
  const pb = /^CVE-(\d+)-(\d+)$/i.exec(b.id);
  if (pa && pb) {
    const yd = Number(pb[1]) - Number(pa[1]);
    if (yd) return yd;
    const sd = Number(pb[2]) - Number(pa[2]);
    if (sd) return sd;
  }
  return b.id.localeCompare(a.id);
}

function applyFilters() {
  const { q, release, status, severity, pkg } = state.filters;
  const needle = q.trim().toLowerCase();
  const pkgNeedle = pkg.trim().toLowerCase();
  return state.entries.filter((e) => {
    if (needle && !e.id.toLowerCase().includes(needle)) return false;
    if (release && !(e.releases || []).includes(release)) return false;
    if (status && e.headline_status !== status) return false;
    if (severity && e.severity !== severity) return false;
    if (pkgNeedle && !(e.packages || []).some((p) => p.toLowerCase().includes(pkgNeedle))) return false;
    return true;
  }).sort(compareCveDesc);
}

function renderControls() {
  const idx = state.index;
  const opt = (val, label, sel) =>
    el("option", { value: val, selected: sel === val ? "selected" : null }, label);

  const releaseSel = el("select", { id: "f-release", "aria-label": "Filter by OS / SKU" }, [
    opt("", "All OS / SKUs", state.filters.release),
    ...(idx.releases || []).map((r) => opt(r, r, state.filters.release)),
  ]);
  const statusSel = el("select", { id: "f-status", "aria-label": "Filter by status" }, [
    opt("", "All statuses", state.filters.status),
    ...(idx.statuses || Object.keys(STATUS_LABELS)).map((s) =>
      opt(s, STATUS_LABELS[s] || s, state.filters.status)),
  ]);
  const sevSel = el("select", { id: "f-sev", "aria-label": "Filter by severity" }, [
    opt("", "All severities", state.filters.severity),
    ...(idx.severities || []).slice().sort((a, b) =>
      (SEVERITY_RANK[a] ?? 9) - (SEVERITY_RANK[b] ?? 9)).map((s) =>
      opt(s, s, state.filters.severity)),
  ]);
  const search = el("input", {
    id: "f-q", type: "search", placeholder: "Search CVE id, e.g. CVE-2026-4",
    value: state.filters.q, autocomplete: "off", spellcheck: "false",
  });
  const pkgInput = el("input", {
    id: "f-pkg", type: "search", placeholder: "e.g. openssl",
    value: state.filters.pkg, autocomplete: "off", spellcheck: "false",
  });

  // Any filter change returns to the first page (the old page may not exist).
  const refilter = () => { state.page = 0; renderList(); };
  search.addEventListener("input", () => { state.filters.q = search.value; refilter(); });
  releaseSel.addEventListener("change", () => { state.filters.release = releaseSel.value; refilter(); });
  statusSel.addEventListener("change", () => { state.filters.status = statusSel.value; refilter(); });
  sevSel.addEventListener("change", () => { state.filters.severity = sevSel.value; refilter(); });
  pkgInput.addEventListener("input", () => { state.filters.pkg = pkgInput.value; refilter(); });

  return el("div", { class: "controls" }, [
    el("div", { class: "field" }, [
      el("label", { for: "f-q" }, [labelWithInfo("Search", "search")]), search]),
    el("div", { class: "field" }, [
      el("label", { for: "f-pkg" }, [labelWithInfo("Package", "pkg_filter")]), pkgInput]),
    el("div", { class: "field" }, [
      el("label", { for: "f-release" }, [labelWithInfo("OS / SKU", "release")]), releaseSel]),
    el("div", { class: "field" }, [
      el("label", { for: "f-status" }, [labelWithInfo("Status", "status")]), statusSel]),
    el("div", { class: "field" }, [
      el("label", { for: "f-sev" }, [labelWithInfo("Severity", "severity")]), sevSel]),
  ]);
}

function renderRows(rows) {
  if (!rows.length) return el("p", { class: "empty" }, "No advisories match your filters.");
  const body = el("tbody", null, rows.map((e) => {
    const releases = (e.releases || []).map((r) => el("span", { class: "chip" }, r));
    return el("tr", null, [
      el("td", { class: "cve" }, el("a", { href: "#/" + e.id }, e.id)),
      el("td", null, severityCell(e.severity)),
      el("td", null, statusBadge(e.headline_status)),
      el("td", null, releases.length ? releases : "\u2014"),
      el("td", { class: "mono muted" }, (e.updated || "").slice(0, 10) || "\u2014"),
    ]);
  }));
  return el("div", { class: "table-wrap" }, el("table", null, [
    el("thead", null, el("tr", null, [
      el("th", null, [labelWithInfo("CVE", "cve")]),
      el("th", null, [labelWithInfo("Severity", "severity")]),
      el("th", null, [labelWithInfo("Status", "status")]),
      el("th", null, [labelWithInfo("OS / SKU", "release")]),
      el("th", null, [labelWithInfo("Updated", "updated")]),
    ])),
    body,
  ]));
}

function renderPager(total, pageSize, pos) {
  const pages = Math.ceil(total / pageSize);
  if (pages <= 1) return null;
  const page = state.page;
  const go = (p) => {
    state.page = p;
    renderList();
    const r = document.getElementById("results");
    if (r && r.scrollIntoView) r.scrollIntoView({ block: "start", behavior: "auto" });
  };
  const prev = el("button", {
    class: "page-btn", type: "button",
    disabled: page <= 0 ? "disabled" : null,
    onclick: () => go(page - 1),
  }, "\u2190 Prev");
  const next = el("button", {
    class: "page-btn", type: "button",
    disabled: page >= pages - 1 ? "disabled" : null,
    onclick: () => go(page + 1),
  }, "Next \u2192");
  const label = el("span", { class: "page-label" }, "Page " + (page + 1) + " of " + pages);
  return el("nav", {
    class: "pager" + (pos ? " pager-" + pos : ""),
    "aria-label": "Advisory list pages" + (pos ? " (" + pos + ")" : ""),
  }, [prev, label, next]);
}

function renderList() {
  // Re-render only the results region when it already exists (keeps focus in
  // the search box); otherwise build the whole view.
  const rows = applyFilters();
  const total = rows.length;
  // Clamp the page into range (filters may have shrunk the result set).
  const maxPage = Math.max(0, Math.ceil(total / LIST_PAGE_SIZE) - 1);
  if (state.page > maxPage) state.page = maxPage;
  if (state.page < 0) state.page = 0;
  const start = state.page * LIST_PAGE_SIZE;
  const pageRows = rows.slice(start, start + LIST_PAGE_SIZE);
  let container = document.getElementById("results");
  if (!container) {
    const meta = el("div", { class: "result-meta" }, [
      el("span", { id: "count" }, ""),
      el("button", { onclick: resetFilters }, "Reset filters"),
    ]);
    const view = el("div", null, [
      el("p", { class: "intro" }, [
        "Fix status of known CVEs in the base-OS packages of recent AKS node images. ",
        el("a", { href: "#/help" }, "How to read this →"),
      ]),
      renderControls(), meta, el("div", { id: "results" }),
    ]);
    $app().replaceChildren(view);
    container = document.getElementById("results");
  }
  // A pager above and below the table: the top one saves a long scroll back up
  // to change pages, the bottom one is reachable right after skimming the rows.
  container.replaceChildren(
    ...[
      renderPager(total, LIST_PAGE_SIZE, "top"),
      renderRows(pageRows),
      renderPager(total, LIST_PAGE_SIZE, "bottom"),
    ].filter(Boolean));
  const count = document.getElementById("count");
  if (count) {
    if (total > LIST_PAGE_SIZE) {
      count.textContent = (start + 1) + "\u2013" + (start + pageRows.length) +
        " of " + total + " matching (" + state.entries.length + " total)";
    } else {
      count.textContent = total + " of " + state.entries.length + " advisories";
    }
  }
  setGeneratedFooter();
}

function resetFilters() {
  state.filters = { q: "", release: "", status: "", severity: "", pkg: "" };
  state.page = 0;
  $app().replaceChildren();  // force full rebuild so control values reset
  renderList();
}

/* ---------- detail view ---------- */

function kv(dl, label, value, helpKey) {
  if (value == null || value === "") return;
  const help = helpKey && FIELD_HELP[helpKey];
  dl.appendChild(el("dt", null, [label, help ? info(help) : null]));
  dl.appendChild(el("dd", null, value));
}

function evidenceLinks(evidence) {
  if (!evidence) return null;
  const items = Object.entries(evidence)
    .filter(([k]) => k !== "retained_vulnerable_version")
    .map(([k, v]) =>
      el("li", null, isExternal(v)
        ? [k.replace(/_/g, " ") + ": ", el("a", { href: v, target: "_blank", rel: "noopener" }, v)]
        : el("span", null, k.replace(/_/g, " ") + ": " + v)));
  if (!items.length) return null;
  return el("ul", { class: "ref-list" }, items);
}

function packageCard(row) {
  const dl = el("dl", { class: "kv" });
  kv(dl, "Status", statusBadge(row.status), "status");
  kv(dl, "Severity", row.severity, "severity");
  kv(dl, "Advisory id", row.advisory_id && el("span", { class: "mono" }, row.advisory_id), "advisory_id");
  kv(dl, "Fixed version", row.fixed_version && el("span", { class: "mono" }, row.fixed_version), "fixed_version");
  kv(dl, "Upstream fixed", row.upstream_fixed_version && el("span", { class: "mono" }, row.upstream_fixed_version), "upstream_fixed_version");
  kv(dl, "First fixed build", row.first_fixed_build && el("span", { class: "mono" }, row.first_fixed_build), "first_fixed_build");
  kv(dl, "Latest build", row.latest_build && el("span", { class: "mono" }, row.latest_build), "latest_build");
  kv(dl, "Justification", row.justification);
  kv(dl, "Statement", row.statement);
  if (row.binary_packages && row.binary_packages.length) {
    // A source row (e.g. linux-azure) standing in for several installed
    // binaries: list them so the collapse hides no information, each linking to
    // its own cross-advisory search.
    const bins = row.binary_packages.map((b, i) => [
      i ? ", " : "",
      el("a", { href: "#/?pkg=" + encodeURIComponent(b), class: "mono pkg-xref",
                title: "Other advisories that name " + b }, b),
    ]).flat();
    kv(dl, "Binary packages", el("span", null, bins), "binary_packages");
  }
  kv(dl, "Retained vulnerable version",
     row.evidence && row.evidence.retained_vulnerable_version &&
       el("span", { class: "mono" }, row.evidence.retained_vulnerable_version),
     "retained_vulnerable_version");
  const ev = evidenceLinks(row.evidence);
  const card = el("div", { class: "card" }, [
    el("h3", null, [
      row.release + " \u00b7 ",
      el("a", {
        href: "#/paths?pkg=" + encodeURIComponent(row.package) +
              (row.release ? "&os=" + encodeURIComponent(row.release) : ""),
        class: "mono pkg-link",
        title: "Show installed paths owned by " + row.package,
      }, row.package),
      " ",
      el("a", {
        href: "#/?pkg=" + encodeURIComponent(row.package),
        class: "pkg-xref", title: "Other advisories that name " + row.package,
      }, "other advisories \u2197"),
    ]),
    dl,
  ]);
  if (ev) {
    card.appendChild(el("h3", null, ["Evidence", info(FIELD_HELP.evidence)]));
    card.appendChild(ev);
  }
  return card;
}

function renderDetail(adv) {
  // Gate href behind isExternal() (same as evidenceLinks) so only http(s)
  // URLs ever become clickable links; anything else renders as inert text.
  const refs = (adv.references || []).map((u) =>
    el("li", null, isExternal(u)
      ? el("a", { href: u, target: "_blank", rel: "noopener" }, u)
      : el("span", null, String(u))));

  const summary = el("div", { class: "card" }, [
    el("h3", null, "Summary"),
    (() => {
      const dl = el("dl", { class: "kv" });
      kv(dl, "Severity", severityCell(adv.severity), "severity");
      kv(dl, "Headline status", statusBadge(adv.headline_status), "status");
      kv(dl, "Updated", (adv.updated || "").slice(0, 10), "updated");
      kv(dl, "Schema", el("span", { class: "mono" }, adv.schema_version));
      return dl;
    })(),
    adv.description ? el("p", { class: "note" }, adv.description) : null,
  ]);

  const refsCard = refs.length
    ? el("div", { class: "card" }, [
        el("h3", null, ["References", info(FIELD_HELP.references)]),
        el("ul", { class: "ref-list" }, refs)])
    : null;

  const pkgCards = (adv.packages || []).map(packageCard);
  const pkgSection = pkgCards.length
    ? el("div", { class: "detail-grid" }, pkgCards)
    : el("p", { class: "empty" }, "No package rows.");

  const add = adv.additive || {};
  const additiveCard = el("div", { class: "card" }, [
    el("h3", null, ["Additive surface", info(FIELD_HELP.additive)]),
    el("p", { class: "note" }, "Coverage: " + (add.coverage || "n/a") + " \u2014 " + (add.note || "")),
    (add.items && add.items.length)
      ? el("ul", { class: "additive-items" }, add.items.map((i) => {
          if (typeof i === "string") return el("li", null, i);
          const cov = i.coverage || "not_assessed";
          const kids = [
            el("span", { class: "comp-name" }, i.name || "?"),
            i.version ? el("span", { class: "comp-ver mono" }, i.version) : null,
            el("span", {
              class: "coverage-badge cov-" + cov,
              title: COVERAGE_HELP[cov] || "",
            }, COVERAGE_LABELS[cov] || cov),
          ];
          if (i.package) {
            kids.push(el("span", { class: "note" }, [
              " \u2192 assessed as package ",
              el("a", { href: "#/?pkg=" + encodeURIComponent(i.package) },
                el("span", { class: "mono" }, i.package)),
            ]));
          }
          return el("li", null, kids.filter(Boolean));
        }))
      : null,
    el("p", { class: "note" }, [
      "See the full ", el("a", { href: "#/components" }, "extended-binaries"),
      " coverage list for every binary and how it is assessed.",
    ]),
  ]);

  const view = el("div", null, [
    el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
    el("div", { class: "detail-head" }, [
      el("h2", null, adv.id),
      severityCell(adv.severity),
      statusBadge(adv.headline_status),
    ]),
    el("div", { class: "detail-grid" }, [summary, refsCard].filter(Boolean)),
    el("p", { class: "section-title" }, [
      "Package status by OS / SKU", info(FIELD_HELP.package)]),
    pkgSection,
    el("div", { style: "margin-top:1.25rem" }, additiveCard),
  ]);
  $app().replaceChildren(view);
}

/* ---------- installed-paths view ---------- */

// Match rows in a pathmap doc. Forward mode (needle set): match the full path or
// its basename. Reverse mode (pkg set, no needle): every path owned by pkg. With
// neither, return every path (browse mode) -- the caller caps how many are shown.
// usr-merge twins that the feed materialized (doc.alias_of maps a derived
// spelling -> the canonical one the distro actually recorded) are collapsed to a
// single row so a human doesn't see /bin/tar and /usr/bin/tar as duplicates;
// agents still get both working keys in by_path. Older feeds have no alias_of, so
// this is a no-op and the table renders exactly as before.
function computePathRows(doc, needle, pkg) {
  const byPath = doc.by_path || {};
  const aliasOf = doc.alias_of || {};
  // Reverse the alias map (canonical -> [derived twin, ...]). A collapsed row
  // must still be findable by the spelling that was collapsed away: the distro
  // records plenty of binaries under /bin (bash, cat, chmod, the btrfs tools),
  // so the canonical row is /bin/bash while a user almost always pastes
  // /usr/bin/bash. Matching only the canonical would report a real indexed path
  // as a miss -- and the miss branch renders the "out of scope, not clean" note,
  // which is precisely the ambiguity this feed exists to remove.
  const twinsOf = {};
  for (const derived of Object.keys(aliasOf)) {
    const canonical = aliasOf[derived];
    (twinsOf[canonical] = twinsOf[canonical] || []).push(derived);
  }
  const nq = (needle || "").trim().toLowerCase();
  const rows = [];
  for (const p of Object.keys(byPath)) {
    if (aliasOf[p]) continue;  // derived twin -> collapsed into its canonical row
    const owners = byPath[p];
    const twins = twinsOf[p] || [];
    if (nq) {
      const spellings = [p].concat(twins);
      const hit = spellings.some((s) =>
        s.toLowerCase().includes(nq)
        || s.slice(s.lastIndexOf("/") + 1).toLowerCase().includes(nq));
      if (!hit) continue;
    } else if (pkg) {
      if (!owners.includes(pkg)) continue;
    }
    // else: no path/pkg filter -> browse the whole map (capped on render).
    rows.push([p, owners, twins]);
  }
  rows.sort((a, b) => a[0].localeCompare(b[0]));
  return rows;
}

const PATH_ROW_CAP = 500;
const PATH_BROWSE_CAP = 100;

function renderPathRows(rows, filtered) {
  if (!rows.length) {
    return el("p", { class: "empty" },
      filtered ? "No installed paths match." : "No installed paths in this map.");
  }
  const cap = filtered ? PATH_ROW_CAP : PATH_BROWSE_CAP;
  const shown = rows.slice(0, cap);
  const body = el("tbody", null, shown.map(([p, owners, twins]) =>
    el("tr", null, [
      el("td", {
        class: "mono",
        title: (twins && twins.length)
          ? "Same file, also resolves as: " + twins.join(", ")
          : null,
      }, p),
      el("td", null, owners.map((pkg, i) => el("span", null, [
        i ? ", " : "",
        el("a", {
          href: "#/?pkg=" + encodeURIComponent(pkg),
          class: "mono pkg-link", title: "Advisories that name " + pkg,
        }, pkg),
      ]))),
    ])));
  const table = el("div", { class: "table-wrap" }, el("table", null, [
    el("thead", null, el("tr", null, [
      el("th", null, [labelWithInfo("Installed path", "path_lookup")]),
      el("th", null, [labelWithInfo("Owning package", "package")]),
    ])),
    body,
  ]));
  if (rows.length > cap) {
    return el("div", null, [
      el("p", { class: "note" }, filtered
        ? ("Showing the first " + cap + " of " + rows.length +
           " matches \u2014 refine your search.")
        : ("Showing the first " + cap + " of " + rows.length +
           " installed paths \u2014 type a path or file name to search.")),
      table,
    ]);
  }
  return table;
}

async function renderPaths(query) {
  $app().replaceChildren(el("p", { class: "loading" }, "Loading installed-path map\u2026"));
  const idx = await loadPathmapIndex();
  if (!idx || !idx.lineages || !Object.keys(idx.lineages).length) {
    $app().replaceChildren(el("div", null, [
      el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
      el("h2", null, "Installed paths"),
      el("p", { class: "empty" },
        "The installed-path \u2192 package map is not available for this feed."),
    ]));
    window.scrollTo(0, 0);
    return;
  }

  const labels = Object.keys(idx.lineages).sort();
  // A deep link's ?os= wins over the sticky filter so a cross-link from an
  // advisory lands on that advisory's lineage; sticky state is the fallback.
  let os = query.get("os") || state.pathFilters.os || idx.default_lineage;
  if (!idx.lineages[os]) os = idx.lineages[idx.default_lineage] ? idx.default_lineage : labels[0];
  state.pathFilters.os = os;

  // A pkg param (cross-link from an advisory) seeds a reverse listing of every
  // path that package owns. Clear any sticky path needle (unless the link itself
  // carries ?q=) so the reverse listing isn't masked by a stale forward search.
  const pkg = query.get("pkg") || "";
  if (query.get("q") != null) state.pathFilters.q = query.get("q");
  else if (pkg) state.pathFilters.q = "";

  let doc;
  try {
    doc = await loadPathmapDoc(idx.lineages[os]);
  } catch (e) {
    $app().replaceChildren(el("div", { class: "error" },
      "Could not load the path map for " + os + " (" + e.message + ")."));
    return;
  }

  const osSel = el("select", { id: "p-os", "aria-label": "OS / SKU for the path map" },
    labels.map((l) => el("option", { value: l, selected: l === os ? "selected" : null }, l)));
  const search = el("input", {
    id: "p-q", type: "search", placeholder: "e.g. /usr/bin/curl or curl",
    value: state.pathFilters.q, autocomplete: "off", spellcheck: "false",
  });

  const results = el("div", { id: "path-results" });
  const refresh = () => {
    const needle = state.pathFilters.q;
    const usePkg = pkg && !needle.trim();
    const filtered = !!(needle.trim() || usePkg);
    const rows = computePathRows(doc, needle, usePkg ? pkg : "");
    const heading = usePkg
      ? el("p", { class: "note" }, ["Installed paths owned by ",
          el("span", { class: "mono" }, pkg), " on ", el("span", { class: "mono" }, os), "."])
      : null;
    // A reverse (pkg) listing with no rows is a common, expected case: many
    // packages own no /bin|/sbin executable (the kernel, shared libraries,
    // config-only packages) and AKS-built/downloaded binaries aren't in the
    // distro file index at all. Explain that and offer the useful next hop
    // instead of a bare "No installed paths match."
    const body = (usePkg && !rows.length)
      ? el("div", { class: "empty" }, [
          el("p", null, ["No indexed executable paths are mapped to ",
            el("span", { class: "mono" }, pkg), " on ",
            el("span", { class: "mono" }, os), "."]),
          el("p", { class: "note" }, ["Only executables under ",
            el("span", { class: "mono" }, "/bin"), " and ",
            el("span", { class: "mono" }, "/sbin"),
            " are indexed. Packages whose files live elsewhere \u2014 the kernel, ",
            "shared libraries, config-only packages \u2014 and binaries AKS builds ",
            "or downloads (e.g. Azure CNI, oras) won't appear here, even though ",
            "they may still be assessed."]),
          el("p", null, el("a", { href: "#/?pkg=" + encodeURIComponent(pkg) },
            ["See advisories that name ", el("span", { class: "mono" }, pkg),
             " \u2192"])),
        ])
      : (filtered && !usePkg && !rows.length)
      // A forward (path) search with no hit is the "is this clean or out of
      // scope?" ambiguity F6 warns about: a miss is NOT evidence the node is
      // unaffected. Say so honestly instead of a bare "No installed paths match."
      ? el("div", { class: "empty" }, [
          el("p", null, "No indexed path matches that search."),
          el("p", { class: "note" }, [
            "A miss here is ", el("strong", null, "not"),
            " evidence the node is unaffected. Only executables under ",
            el("span", { class: "mono" }, "/bin"), " and ",
            el("span", { class: "mono" }, "/sbin"),
            " are indexed, so a library (", el("span", { class: "mono" }, "/usr/lib"),
            ") or a path under ", el("span", { class: "mono" }, "/opt"),
            " not listed here is out of scope, not clean. Try the file name alone ",
            "(e.g. ", el("span", { class: "mono" }, "curl"),
            ") in case your scanner reported a different directory."]),
        ])
      : renderPathRows(rows, filtered);
    results.replaceChildren(...[heading, body].filter(Boolean));
  };

  search.addEventListener("input", () => { state.pathFilters.q = search.value; refresh(); });
  osSel.addEventListener("change", () => {
    state.pathFilters.os = osSel.value;
    // Rebuild the whole view so the newly selected map is fetched/cached.
    location.hash = "#/paths?os=" + encodeURIComponent(osSel.value) +
      (state.pathFilters.q ? "&q=" + encodeURIComponent(state.pathFilters.q) : "");
  });

  const meta = idx.maps && idx.maps.find((m) => m.key === idx.lineages[os]);
  // Count canonical paths (excluding materialized usr-merge twins) so the meta
  // line matches the collapsed table a human sees. Older feeds have no alias_of,
  // so aliasCount is 0 and this equals meta.path_count exactly.
  const aliasCount = doc.alias_of ? Object.keys(doc.alias_of).length : 0;
  const view = el("div", null, [
    el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
    el("h2", null, "Installed paths \u2192 package"),
    el("p", { class: "intro" }, [
      "Map an install path your scanner reported (e.g. ", el("span", { class: "mono" }, "/usr/bin/curl"),
      ") to the package it belongs to, then jump to that package's advisories. ",
      el("a", { href: "#/help" }, "How this works \u2192"),
    ]),
    el("div", { class: "controls" }, [
      el("div", { class: "field" }, [
        el("label", { for: "p-os" }, [labelWithInfo("OS / SKU", "path_os")]), osSel]),
      el("div", { class: "field grow" }, [
        el("label", { for: "p-q" }, [labelWithInfo("Path or file name", "path_lookup")]), search]),
    ]),
    meta ? el("p", { class: "result-meta muted" },
      (meta.path_count - aliasCount) + " executable paths \u00b7 " +
      meta.package_count + " packages indexed.") : null,
    results,
  ]);
  $app().replaceChildren(view);
  refresh();
  window.scrollTo(0, 0);
}

/* ---------- help view ---------- */

// A measured share for a status, from the generated glossary counts. Returns
// null when no glossary was loaded (older feed) so the legend simply omits it.
function statusShareNote(status) {
  const st = state.glossary.data && state.glossary.data.status;
  if (!st || !st.counts || !st.total) return null;
  const n = st.counts[status] || 0;
  const share = st.shares && st.shares[status];
  const pct = share != null
    ? (share * 100).toFixed(1) + "%"
    : Math.round((100 * n) / st.total) + "%";
  return el("span", { class: "gloss-count muted" },
    n.toLocaleString() + " \u00b7 " + pct + " of advisories");
}

function statusGlossary() {
  return el("div", { class: "glossary" }, Object.keys(STATUS_LABELS).map((s) =>
    el("div", { class: "gloss-row" }, [
      el("div", { class: "gloss-key" }, [statusBadge(s), statusShareNote(s)]),
      el("p", null, STATUS_HELP[s]),
    ])));
}

function coverageGlossary() {
  return el("div", { class: "glossary" }, Object.keys(COVERAGE_LABELS).map((c) =>
    el("div", { class: "gloss-row" }, [
      el("span", { class: "coverage-badge cov-" + c }, COVERAGE_LABELS[c]),
      el("p", null, COVERAGE_HELP[c]),
    ])));
}

// The components "Assessed as / why not" cell. covered_by_package links to the
// distro package that tracks it; covered_by_scan links to the component's own
// scan-derived advisories; scan_pending carries its own note; every other
// coverage class gets a short reason so the column is never a bare em-dash.
function assessedCell(i) {
  if (i.package) {
    return el("a", { href: "#/?pkg=" + encodeURIComponent(i.package),
      class: "mono pkg-link", title: "Advisories that name " + i.package }, i.package);
  }
  // Normalize coverage the same way the badge does, so a row missing coverage
  // (or a scan_pending row missing its note) never degrades to a bare em-dash.
  const coverage = i.coverage || "not_assessed";
  if (coverage === "covered_by_scan") {
    return el("a", { href: "#/?pkg=" + encodeURIComponent(i.name),
      class: "pkg-link", title: "Scan-derived advisories for " + i.name },
      "scan advisories \u2192");
  }
  if (i.note) return el("span", { class: "note" }, i.note);
  return el("span", { class: "note" }, COVERAGE_WHY[coverage] || "\u2014");
}

function renderHelp() {
  const view = el("div", { class: "help" }, [
    el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
    el("h2", null, "Help & glossary"),

    el("p", { class: "note" }, [
      "This site reports the fix status of known CVEs in the ",
      el("strong", null, "base-OS packages"),
      " (Azure Linux and Ubuntu) of recent AKS node images (VHDs). It is a ",
      "community project generated by an open-source tool",
      " \u2014 it is not an official Microsoft security feed.",
    ]),

    el("h3", null, "Status vocabulary"),
    el("p", { class: "note" }, "Each CVE gets a single headline status (the most actionable across all OS/SKU lineages). On an advisory page you can see each lineage's own status."),
    statusGlossary(),
    state.glossary.data && state.glossary.data.status && state.glossary.data.status.total
      ? el("p", { class: "note muted" },
        "The share shown beside each status is measured from this build's " +
        state.glossary.data.status.total.toLocaleString() +
        " advisories (from data/glossary.json), not a fixed estimate.")
      : null,

    el("h3", null, "Columns & fields"),
    (() => {
      const dl = el("dl", { class: "kv help-kv" });
      const order = ["cve", "severity", "status", "release", "updated",
        "package", "fixed_version", "upstream_fixed_version",
        "first_fixed_build", "latest_build", "advisory_id", "evidence",
        "references", "additive"];
      for (const k of order) {
        dl.appendChild(el("dt", null, k.replace(/_/g, " ")));
        dl.appendChild(el("dd", null, FIELD_HELP[k]));
      }
      return dl;
    })(),

    el("h3", null, "How the feed is built"),
    el("ul", { class: "bullets" }, [
      el("li", null, "The CVE universe is the distro OVAL feed intersected with the packages actually installed in the newest scanned VHD build."),
      el("li", null, "For each affected package the tool scans a set of recent VHD build release notes (anchored at a fixed floor version, e.g. the start of the year) plus the latest security-patch deltas, and records the earliest build that reaches the fixed version."),
      el("li", null, "Azure Linux uses Microsoft's OVAL plus the MSRC CSAF/VEX feed (for not_affected / under_investigation / affected verdicts); Ubuntu uses Canonical's per-release CVE OVAL plus the Ubuntu CVE Tracker (for not_affected / under_investigation / affected / will_not_fix verdicts)."),
      el("li", null, "The Linux kernel is assessed too. Canonical encodes kernel fixes differently from ordinary packages, so the tool reads them separately and reports a single 'linux-azure' row that rolls up its many installed binaries (linux-image-*/linux-headers-*/\u2026). Azure Linux tracks its kernel as an ordinary package, so it needs no special handling."),
    ]),

    el("h3", null, "Known limitations"),
    el("ul", { class: "bullets" }, [
      el("li", null, [el("strong", null, "Additive surface only partly assessed. "),
        FIELD_HELP.additive]),
      el("li", null, [el("strong", null, "'Affected' comes only from vendor verdicts. "),
        "A CVE with no upstream fix can't be enumerated from OVAL alone, so 'affected' is surfaced only where the vendor VEX / Ubuntu CVE Tracker asserts it; otherwise the feed reports fixed / fix_available_upstream / under_investigation. See the measured share beside each status above for how much of this build it is."]),
      el("li", null, [el("strong", null, "Windowed. "),
        "Only CVEs whose fix status is determined within the scanned build window appear; issues fixed before the window are treated as old news."]),
      el("li", null, [el("strong", null, "FIPS / some confidential-VM kernels not assessed. "),
        "A few Ubuntu FIPS and CVM node images list no kernel binary in their release notes (only kernel tooling), so their running kernel version can't be observed and their kernel is left unassessed. FIPS kernels are also tracked only in a separate Ubuntu Pro FIPS feed, outside this public data. Other lineages' kernels \u2014 including noble CVM (full-disk-encryption) images \u2014 are covered."]),
    ]),

    el("h3", null, "Ordering"),
    el("p", { class: "note" }, "Advisories are listed newest CVE first \u2014 sorted by CVE year then sequence number (descending). There is no per-CVE publication date in the feed, so the CVE id is used as a recency proxy. The Updated column shows when the record was last regenerated by the daily feed build, which is the same date for every row in a given run."),

    el("h3", null, "Using search & filters"),
    el("ul", { class: "bullets" }, [
      el("li", null, "Search matches a CVE id substring (e.g. \"2026-4\")."),
      el("li", null, "OS / SKU filters by VHD lineage label; Status and Severity narrow further. Combine them freely, then Reset to clear."),
    ]),

    el("h3", null, ["Extended-binary coverage", info(FIELD_HELP.components)]),
    el("p", { class: "note" }, ["Binaries AKS lays on top of the base OS image (see the ",
      el("a", { href: "#/components" }, "Extended binaries"),
      " page) each get a coverage class describing whether \u2014 and how \u2014 the distro ",
      "advisory feeds assess them."]),
    coverageGlossary(),

    el("h3", null, ["Installed paths \u2192 package", info(FIELD_HELP.paths)]),
    el("p", { class: "note" }, [
      "Scanners report a file path (e.g. ", el("span", { class: "mono" }, "/usr/bin/curl"),
      "), but advisories are keyed by package name. The ",
      el("a", { href: "#/paths" }, "Installed paths"),
      " page maps an executable path back to its owning package for a chosen OS/SKU, ",
      "so you can find the right advisory. Only executables under ",
      el("span", { class: "mono" }, "/bin"), " and ", el("span", { class: "mono" }, "/sbin"),
      " are indexed \u2014 the paths scanners surface. Path ownership is stable within an ",
      "OS release, so every SKU of a release shares one map; the default is the mainstream ",
      "Azure Linux 3 gen2 image. From an advisory, each package name links to its installed paths, ",
      "and each path links back to the advisories that name its package.",
    ]),

    el("h3", null, "Data contract"),
    el("p", { class: "note" }, "The feed is plain JSON you can consume directly. Shapes:"),
    el("dl", { class: "kv help-kv" }, [
      el("dt", null, "data/index.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, generated, count, releases[], statuses[], severities[], advisories[] }"),
        " \u2014 each advisories[] entry: ",
        el("span", { class: "mono" },
          "{ id, headline_status, severity, updated, releases[], packages[], summary? }"),
        "."]),
      el("dt", null, "data/manifest.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, type, generated, data_root, count, endpoints[] }"),
        " \u2014 generated inventory of every endpoint with real byte sizes; read it first to plan fetches and avoid the large index. Optional (may be absent on older feeds)."]),
      el("dt", null, "data/index-slim.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, type, count, generated, advisories[{ id, headline_status, severity? }] }"),
        " \u2014 id + headline_status + severity only (~3-4% of index.json). Optional."]),
      el("dt", null, "data/by-package/index.json + <file>.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ \u2026 packages[{ name, file, count }], aliases[{ name, alias_of, file }]? }"),
        " maps a package name to its per-package file: ",
        el("span", { class: "mono" },
          "{ package, count, releases[], advisories[{ id, headline_status, severity?, releases:[int\u2026] }] }"),
        " (release labels interned). A (package, CVE) lookup is \u22642 fetches. Optional."]),
      el("dt", null, "data/by-release/index.json + <file>.json"),
      el("dd", null, [
        "Same, keyed by VHD lineage label; per-release file interns the package names. Optional."]),
      el("dt", null, "data/advisories/<CVE>.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, id, severity, headline_status, updated, description?, references[], packages[], additive }"),
        " \u2014 each packages[] row: ",
        el("span", { class: "mono" },
          "{ package, release, status, severity, advisory_id?, fixed_version?, upstream_fixed_version?, first_fixed_build?, latest_build?, justification?, statement?, evidence? }"),
        "."]),
      el("dt", null, "data/pathmap/index.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, generated, default_lineage, lineages{label\u2192key}, maps[] }"),
        "."]),
      el("dt", null, "data/pathmap/<key>.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, type, key, os_family, release, path_count, package_count, owner_scope, indexed_prefixes[], usr_merge, path_normalization{}, coverage_note, ambiguous_paths[], alias_of{derived\u2192canonical}, by_path{path\u2192[package,\u2026]}, by_base{basename\u2192[package,\u2026]}, packages[name,\u2026] }"),
        " \u2014 scoped to installed packages and usr-merge normalized; a miss is not \u201cnot vulnerable\u201d (see coverage_note)."]),
      el("dt", null, "data/components.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, type, generated, families{family\u2192{components[], counts{}}} }"),
        " \u2014 each components[] item: ",
        el("span", { class: "mono" },
          "{ name, coverage, version?, package?, note? }"),
        "."]),
      el("dt", null, "data/glossary.json"),
      el("dd", null, [el("span", { class: "mono" },
        "{ schema_version, type, generated, status{labels,help,counts,shares,total,counts_basis}, coverage{labels,help,why,counts,shares,total}, field{help} }"),
        " \u2014 the status / coverage / field vocabulary with per-value counts and shares measured from this build (optional; older feeds may not publish it, in which case the app uses a baked-in copy). status.counts/shares are the per-advisory headline distribution (one most-actionable status per advisory), NOT per-package prevalence \u2014 see status.counts_basis (issue #39, F7)."]),
    ]),
    el("p", { class: "note" }, [
      "Status values: ",
      el("span", { class: "mono" }, Object.keys(STATUS_LABELS).join(", ")),
      ". A canonical, versioned copy of this data contract is published in the ",
      el("a", { href: "https://github.com/chrischangcode/chrischangcode.github.io/blob/main/DATA-CONTRACT.md", target: "_blank", rel: "noopener" },
        "public site repository"),
      ".",
    ]),
  ]);
  $app().replaceChildren(view);
  window.scrollTo(0, 0);
}

/* ---------- extended-binaries (components) view ---------- */

async function renderComponents(query) {
  $app().replaceChildren(el("p", { class: "loading" }, "Loading extended-binary coverage\u2026"));
  const man = await loadComponents();
  if (!man || !man.families || !Object.keys(man.families).length) {
    $app().replaceChildren(el("div", null, [
      el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
      el("h2", null, "Extended binaries"),
      el("p", { class: "empty" },
        "The extended-binary coverage manifest is not available for this feed."),
    ]));
    window.scrollTo(0, 0);
    return;
  }

  const fams = Object.keys(man.families).sort();
  let fam = state.componentFilters.os || query.get("os") || fams[0];
  if (!man.families[fam]) fam = fams[0];
  state.componentFilters.os = fam;
  if (query.get("coverage") != null) state.componentFilters.coverage = query.get("coverage");
  const cov = state.componentFilters.coverage || "";

  const famSel = el("select", { id: "c-fam", "aria-label": "OS family" },
    fams.map((f) => el("option", { value: f, selected: f === fam ? "selected" : null }, f)));
  const covSel = el("select", { id: "c-cov", "aria-label": "Coverage" },
    [el("option", { value: "", selected: cov === "" ? "selected" : null }, "All coverage"),
     ...Object.keys(COVERAGE_LABELS).map((c) =>
       el("option", { value: c, selected: c === cov ? "selected" : null }, COVERAGE_LABELS[c]))]);

  const results = el("div", { id: "comp-results" });
  const refresh = () => {
    const entry = man.families[state.componentFilters.os] || { components: [], counts: {} };
    const items = entry.components.filter((i) =>
      !state.componentFilters.coverage || i.coverage === state.componentFilters.coverage);
    const counts = entry.counts || {};
    const summary = el("p", { class: "note" }, Object.keys(COVERAGE_LABELS)
      .filter((c) => counts[c])
      .map((c) => el("span", { class: "coverage-badge cov-" + c, style: "margin-right:.4rem" },
        COVERAGE_LABELS[c] + ": " + counts[c])));
    const body = el("tbody", null, items.map((i) => el("tr", null, [
      el("td", null, el("span", { class: "comp-name" }, i.name)),
      el("td", { class: "mono" }, i.version || "\u2014"),
      el("td", null, el("span", {
        class: "coverage-badge cov-" + (i.coverage || "not_assessed"),
        title: COVERAGE_HELP[i.coverage] || "",
      }, COVERAGE_LABELS[i.coverage] || i.coverage)),
      el("td", null, assessedCell(i)),
    ])));
    const table = el("div", { class: "table-wrap" }, el("table", null, [
      el("thead", null, el("tr", null, [
        el("th", null, "Extended binary"),
        el("th", null, "Version"),
        el("th", null, [labelWithInfo("Coverage", "components")]),
        el("th", null, "Assessed as / why not"),
      ])),
      body,
    ]));
    results.replaceChildren(summary, items.length ? table
      : el("p", { class: "empty" }, "No extended binaries match."));
  };

  famSel.addEventListener("change", () => {
    state.componentFilters.os = famSel.value;
    refresh();
  });
  covSel.addEventListener("change", () => {
    state.componentFilters.coverage = covSel.value;
    refresh();
  });

  const view = el("div", null, [
    el("a", { class: "back", href: "#/" }, "\u2190 All advisories"),
    el("div", { class: "detail-head" }, [
      el("h2", null, ["Extended binaries", info(FIELD_HELP.components)]),
    ]),
    el("p", { class: "note" }, [
      "AKS lays additional binaries on top of the base OS image. Some are the ",
      "same artifact as an installed distro package (so their CVE status is in the ",
      el("a", { href: "#/" }, "advisories"),
      "); others are AKS-built/upstream or installed only on some SKUs. This page ",
      "shows how each one is \u2014 or is not \u2014 assessed by the distro advisory feeds.",
    ]),
    el("div", { class: "filters" }, [
      el("label", null, ["OS family ", famSel]),
      el("label", null, ["Coverage ", covSel]),
    ]),
    results,
  ]);
  $app().replaceChildren(view);
  refresh();
  window.scrollTo(0, 0);
}

/* ---------- footer / routing ---------- */

function setGeneratedFooter() {
  const g = document.getElementById("feed-generated");
  if (g && state.index && state.index.generated) {
    g.textContent = "Feed generated " + state.index.generated +
      " \u00b7 " + state.index.count + " advisories.";
  }
}

// Split the hash into a path and a query string, supporting deep links like
// `#/paths?pkg=curl&os=AKSAzureLinuxV3/gen2` and `#/?pkg=curl`.
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const qi = raw.indexOf("?");
  const path = qi >= 0 ? raw.slice(0, qi) : raw;
  const query = new URLSearchParams(qi >= 0 ? raw.slice(qi + 1) : "");
  return { path, query };
}

async function route() {
  if (!state.index) return;  // initial load handles first render
  const { path, query } = parseHash();
  if (/^help$/i.test(path)) {
    renderHelp();
  } else if (/^paths$/i.test(path)) {
    await renderPaths(query);
  } else if (/^components$/i.test(path)) {
    await renderComponents(query);
  } else if (path) {
    // Any non-reserved, non-empty path is an advisory id. IDs come from several
    // schemes -- CVE-*, GO-* (Go vuln DB), GHSA-* (GitHub advisories) -- so match
    // them all rather than a single prefix. Advisory files are stored uppercase.
    $app().replaceChildren(el("p", { class: "loading" }, "Loading " + path + "\u2026"));
    try {
      renderDetail(await loadAdvisory(path.toUpperCase()));
    } catch (e) {
      $app().replaceChildren(el("div", { class: "error" },
        "Could not load advisory " + path + " (" + e.message + ")."));
    }
    window.scrollTo(0, 0);
  } else {
    // List view, optionally seeded by a `?pkg=` deep link (from a cross-link).
    state.filters.pkg = query.get("pkg") || "";
    state.page = 0;
    $app().replaceChildren();  // force a full rebuild so control values reflect state
    renderList();
  }
}

async function main() {
  try {
    await loadIndex();
  } catch (e) {
    $app().replaceChildren(el("div", { class: "error" },
      "Failed to load the advisory feed (" + e.message + "). " +
      "If running locally, serve the repo root and open /site/vhd/, or pass ?data=<path>."));
    return;
  }
  // First paint must not wait on the optional glossary. Render immediately from
  // index.json, then load glossary.json off the critical path and re-render the
  // current view only if a document actually arrived. A missing (404) or hung
  // glossary can therefore never delay or block first paint -- loadGlossary is
  // itself time-boxed as a second line of defence. This is the live path today:
  // production 404s glossary.json until the next weekly feed build publishes it.
  setGeneratedFooter();
  window.addEventListener("hashchange", route);
  await route();
  // LOAD-BEARING ORDER: route() (first paint) must run and be awaited BEFORE this
  // line, and this loadGlossary() call must stay fire-and-forget (NOT awaited).
  // Awaiting the optional glossary here reintroduces the blocking-hang bug (a
  // stalled glossary.json would freeze first paint). Enforced by
  // tests/test_vocab.py::MainRenderOrderTest -- do not "tidy" into an await.
  loadGlossary().then((doc) => { if (doc) route(); });
}

document.addEventListener("DOMContentLoaded", main);
