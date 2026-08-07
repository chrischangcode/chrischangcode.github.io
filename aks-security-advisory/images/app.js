/*
 * AKS Container Image Security Advisories — static front-end (issue #40, Phase 3).
 *
 * Zero build step, zero dependencies. It reads the JSON feed produced by
 * `aks-cve images-feed` (aksadvisory.feed.ccp): a small `_index.json` entry
 * point, then per-Kubernetes-version (`k8s/<version>.json`), per-CVE
 * (`cve/<CVE>.json`), per-AKS-release (`release/<version>.json`) and, when the
 * feed publishes it, per-image (`image/<slug>.json`) documents.
 *
 * Data location: see `candidateDataBases()`. This app lives in `site/images/`;
 * the feed deploys to `images/data/` — i.e. `data` relative to this app (a
 * SIBLING of the VHD `data/` tree, NOT one level up). For local preview
 * (`python -m http.server` from the repo root, open `/site/images/`) it falls
 * back to `../../feed-out/images` (a repo-root `feed-out/images/` build). A
 * `?data=<base>` query override wins over both.
 *
 * Six correctness rules from issue #40 are load-bearing and enforced throughout:
 *   1. The Kubernetes snapshot axis and the AKS release-history axis are NEVER
 *      blended into one number/table; every row is labelled with its `basis`.
 *   2. Absence of a CVE from a scan is "not observed", never "not affected".
 *   3. Scan staleness (report_time / scan_age_days / cohort / comparable_with)
 *      is always visible; cross-cohort comparison is warned about.
 *   4. No invented severity — the upstream API publishes none.
 *   5. The state vocabulary is rendered from glossary.json (with a baked-in
 *      fallback pinned equal to Python by tests/test_ccp_site_vocab.py).
 *   6. Unknown enum values from a newer feed fall back gracefully, never blank.
 */
"use strict";

/* ---------- glossary (single source of truth for tooltips + help page) ----------
 *
 * These objects are the BAKED-IN FALLBACK. The canonical vocabulary lives in
 * Python (aksadvisory/feed/ccp/vocab.py) and is emitted as `data/glossary.json`
 * with per-value counts measured from the build. `loadGlossary()` prefers that
 * document, replacing these defaults section-by-section (see `applyGlossary`);
 * when it is absent (the images feed can 404 entirely on a first deploy — the
 * site can ship ahead of the feed) these baked copies keep every tooltip and the
 * help page working. They MUST stay identical to vocab.py — tests/
 * test_ccp_site_vocab.py fails if they drift. They are `let`, not `const`, so the
 * generated glossary can override them at runtime. */

// Attribution states: how an AKS-release image maps onto the Kubernetes axis.
let ATTRIBUTION_LABELS = {
  k8s_exact: "Exact match",
  k8s_repo_tagskew: "Repo match, tag skew",
  k8s_registry_variant: "Registry-path variant",
  k8s_unmapped: "Not mapped to a Kubernetes version",
};

let ATTRIBUTION_HELP = {
  k8s_exact: "The AKS-release image matches an image in a frozen Kubernetes snapshot exactly -- same repo:tag, or same sha256 digest. The strongest attribution claim.",
  k8s_repo_tagskew: "The image repository matches a Kubernetes snapshot but the tag differs: the AKS release train moved ahead of the frozen snapshot. The component is the same; the exact build is not.",
  k8s_registry_variant: "The repository matches only after conservative registry-path normalization (e.g. an oss/ vs containernetworking/ spelling of the same component). The component is the same; the registry path differs.",
  k8s_unmapped: "This image is absent from every frozen Kubernetes snapshot, so it cannot be attributed to any Kubernetes version. It is listed under its AKS release version(s) only. This is the demonstrable fact; the feed does NOT claim a reason (e.g. 'served regardless of Kubernetes version') the data cannot establish.",
};

// The single demonstrable reason attached to a k8s_unmapped image.
let UNMAPPED_REASON_HELP = {
  absent_from_all_k8s_reports: "The image reference does not appear in any per-Kubernetes-version scan report. This is the only claim made about an unmapped image.",
};

// First-fixed source: provenance of a first-fix record on the release axis.
let FIRST_FIXED_SOURCE_LABELS = {
  computed: "Computed (upstream agrees)",
  upstream: "Upstream only",
  disputed: "Disputed",
};

let FIRST_FIXED_SOURCE_HELP = {
  computed: "First-fix computed by diffing active_cves across the AKS release chain, and the upstream mitigated_cves_from_previous_release list agrees. The confident case.",
  upstream: "The target could not be compared across releases (e.g. the oldest release, or a target new in this release), so the upstream mitigated_cves_from_previous_release list is used verbatim.",
  disputed: "The computed diff and the upstream mitigated list disagree for this CVE. The feed records both signals (in_computed / in_upstream) rather than silently choosing one.",
};

// CVE presentation states: the per (k8s version, image, CVE) cell state.
let PRESENTATION_LABELS = {
  active: "Active",
  not_affected: "Not affected",
  not_present: "Not present on this version",
  not_assessed: "Not assessed",
  unknown_not_tracked: "Fix history not tracked",
};

let PRESENTATION_HELP = {
  active: "The scanner reports this CVE on this image on this Kubernetes version. Stored as an explicit fact in k8s/<version>.json and cve/<CVE>.json.",
  not_affected: "The image runs on this Kubernetes version and its scan does NOT report the CVE. Derived: the image is listed in k8s/<version>.json but the CVE is not among its active_cves.",
  not_present: "This image does not run on this Kubernetes version. Derived: the image is not listed in k8s/<version>.json.",
  not_assessed: "This Kubernetes version has no scan report. Derived: the version is not listed in _index.json. It is NEVER a missing key -- absence of a version from the index is the explicit signal, not clean.",
  unknown_not_tracked: "The image is not tracked in the AKS release train, so its fix history is unavailable and 'the first AKS release that fixes this' cannot be answered. Not the same as 'not fixed'.",
};

// Basis: which endpoint a record came from. The three are never blended.
let BASIS_LABELS = {
  k8s_snapshot: "Kubernetes snapshot",
  release_history: "AKS release history",
  image_current: "Per-image (current) scan",
};

let BASIS_HELP = {
  k8s_snapshot: "From a frozen per-Kubernetes-version scan report. Counts are only comparable within a report_time cohort (see comparable_with).",
  release_history: "Derived from the AKS release chain (mitigation history + computed diffs). The only axis that answers 'when was this fixed?'.",
  image_current: "From a continuously-rescanned per-image report. Drifts ahead of the frozen snapshots, so it is never blended with them.",
};

/* ---------- state ---------- */

const DEPLOYED_DATA_BASE = "data";               // images/data/ (sibling of VHD data/)
const LOCAL_DEV_DATA_BASE = "../../feed-out/images";

const state = {
  dataBase: DEPLOYED_DATA_BASE,
  index: null,                       // parsed _index.json
  k8sCache: new Map(),               // version -> k8s/<version>.json
  cveCache: new Map(),               // id -> cve/<CVE>.json
  releaseDocs: null,                 // {version: release/<version>.json}, loaded lazily
  releaseTried: false,
  releaseLoad: { failed: 0, total: 0 }, // health of the release-doc fetch (fix #3)
  firstFixIndex: null,               // cve -> [first-fix record...], derived from releaseDocs
  imageIndex: undefined,             // image/index.json ({name->file}); null once tried+absent
  imageDocCache: new Map(),
  glossary: { data: null, tried: false },
  bulk: { raw: "", results: null, version: null },  // Screen 2 bulk-triage state
};

const $app = () => document.getElementById("app");

// Force a conditional revalidation so a rebuilt feed is picked up, but an
// unchanged file returns a tiny 304 (same reasoning as the VHD app).
const REVALIDATE = { cache: "no-cache" };

/* ---------- feed location ---------- */

function candidateDataBases() {
  const override = new URLSearchParams(location.search).get("data");
  const strip = (b) => b.replace(/\/+$/, "");
  return override ? [strip(override)] : [DEPLOYED_DATA_BASE, LOCAL_DEV_DATA_BASE];
}

// A base is accepted only when it returns parseable JSON with a `k8s_versions`
// array, so a host that answers 200 with an HTML fallback for a missing file
// cannot be mistaken for a feed.
function looksLikeImagesIndex(doc) {
  return !!doc && typeof doc === "object" && Array.isArray(doc.k8s_versions);
}

async function loadIndex() {
  const tried = [];
  for (const base of candidateDataBases()) {
    let r;
    try {
      r = await fetch(base + "/_index.json", REVALIDATE);
    } catch (e) {
      tried.push(base + " (network error)");
      continue;
    }
    if (!r.ok) { tried.push(base + " (HTTP " + r.status + ")"); continue; }
    let doc;
    try { doc = await r.json(); } catch (_e) { tried.push(base + " (not JSON)"); continue; }
    if (!looksLikeImagesIndex(doc)) { tried.push(base + " (no k8s_versions[])"); continue; }
    state.dataBase = base;
    state.index = doc;
    return;
  }
  throw new Error("no images feed index found — tried " + tried.join("; "));
}

async function fetchJson(rel) {
  const r = await fetch(state.dataBase + "/" + rel, REVALIDATE);
  if (!r.ok) { const e = new Error(rel + " HTTP " + r.status); e.status = r.status; throw e; }
  return r.json();
}

async function loadK8s(version) {
  if (state.k8sCache.has(version)) return state.k8sCache.get(version);
  const doc = await fetchJson("k8s/" + encodeURIComponent(version) + ".json");
  state.k8sCache.set(version, doc);
  return doc;
}

async function loadCve(id) {
  if (state.cveCache.has(id)) return state.cveCache.get(id);
  const doc = await fetchJson("cve/" + encodeURIComponent(id) + ".json");
  state.cveCache.set(id, doc);
  return doc;
}

// Load every AKS-release document once and index its first-fix records by CVE.
// Best-effort: any release doc that 404s is skipped, so Path B degrades to
// "fix history unavailable" rather than erroring. Bounded (~15 small files).
async function loadFirstFixIndex() {
  if (state.releaseTried) return state.firstFixIndex;
  state.releaseTried = true;
  const versions = (state.index.aks_releases || []).map((r) => r.version);
  let failed = 0;
  const docs = await Promise.all(versions.map(async (v) => {
    try { return await fetchJson("release/" + encodeURIComponent(v) + ".json"); }
    catch (_e) { failed++; return null; }
  }));
  // Record load health so a FAILED fetch is never presented as the substantive
  // finding "no fix recorded". A network/HTTP error that leaves the chain
  // incomplete must read as "could not load", not reassurance (rule 2).
  state.releaseLoad = { failed: failed, total: versions.length };
  const order = {};
  versions.forEach((v, i) => { order[v] = i; });   // oldest -> newest by index order
  const idx = {};
  for (const doc of docs) {
    if (!doc) continue;
    for (const ff of doc.first_fixes || []) {
      (idx[ff.cve] = idx[ff.cve] || []).push(ff);
    }
  }
  // Earliest release first, so idx[cve][0] is the first AKS release with a fix.
  for (const cve of Object.keys(idx)) {
    idx[cve].sort((a, b) => (order[a.release] ?? 1e9) - (order[b.release] ?? 1e9));
  }
  state.firstFixIndex = idx;
  return idx;
}

// Per-image documents (image/<slug>.json), resolved through the authoritative
// image/index.json name->file map — NEVER by guessing a filename. Returns
// `null` (not undefined) once the index has been tried and found absent, so
// Screen 4 can degrade with an honest message.
async function loadImageIndex() {
  if (state.imageIndex !== undefined) return state.imageIndex;
  try {
    state.imageIndex = await fetchJson("image/index.json");
  } catch (_e) {
    state.imageIndex = null;
  }
  return state.imageIndex;
}

async function loadImageDoc(file) {
  if (state.imageDocCache.has(file)) return state.imageDocCache.get(file);
  const doc = await fetchJson("image/" + file);
  state.imageDocCache.set(file, doc);
  return doc;
}

/* ---------- glossary loading ---------- */

// Replace a baked section wholesale when the generated one is a non-empty
// object, so a key the feed no longer publishes cannot survive from the stale
// baked copy; a missing/garbled section falls back to the baked copy in full.
function applyGlossary(doc) {
  if (!doc || typeof doc !== "object") return;
  const attr = doc.attribution || {};
  const ff = doc.first_fixed_source || {};
  const ps = doc.presentation_state || {};
  const basis = doc.basis || {};
  const pick = (o, baked) =>
    (o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length) ? o : baked;
  ATTRIBUTION_LABELS = pick(attr.labels, ATTRIBUTION_LABELS);
  ATTRIBUTION_HELP = pick(attr.help, ATTRIBUTION_HELP);
  UNMAPPED_REASON_HELP = pick(attr.unmapped_reason_help, UNMAPPED_REASON_HELP);
  FIRST_FIXED_SOURCE_LABELS = pick(ff.labels, FIRST_FIXED_SOURCE_LABELS);
  FIRST_FIXED_SOURCE_HELP = pick(ff.help, FIRST_FIXED_SOURCE_HELP);
  PRESENTATION_LABELS = pick(ps.labels, PRESENTATION_LABELS);
  PRESENTATION_HELP = pick(ps.help, PRESENTATION_HELP);
  BASIS_LABELS = pick(basis.labels, BASIS_LABELS);
  BASIS_HELP = pick(basis.help, BASIS_HELP);
}

async function loadGlossary() {
  if (state.glossary.tried) return state.glossary.data;
  state.glossary.tried = true;
  try {
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

function info(text) {
  if (!text) return null;
  return el("span", {
    class: "info", tabindex: "0", role: "note",
    "data-tip": text, "aria-label": text, title: text,
  }, "\u24D8");
}

function isExternal(url) { return /^https?:\/\//i.test(url || ""); }

// Forward-compatible label lookup: an unknown enum value from a newer feed
// renders as a humanised version of the raw key rather than blank (rule 6).
function labelOf(map, key) {
  if (map && Object.prototype.hasOwnProperty.call(map, key)) return map[key];
  return (key || "\u2014").replace(/_/g, " ");
}

function stateBadge(st) {
  return el("span", {
    class: "badge img-st img-st-" + st,
    title: labelOf(PRESENTATION_LABELS, st) + " — " + (PRESENTATION_HELP[st] || ""),
  }, labelOf(PRESENTATION_LABELS, st));
}

function attrBadge(st) {
  return el("span", {
    class: "badge attr attr-" + st,
    title: labelOf(ATTRIBUTION_LABELS, st) + " — " + (ATTRIBUTION_HELP[st] || ""),
  }, labelOf(ATTRIBUTION_LABELS, st));
}

function basisBadge(b) {
  return el("span", {
    class: "badge basis basis-" + b,
    title: labelOf(BASIS_LABELS, b) + " — " + (BASIS_HELP[b] || ""),
  }, labelOf(BASIS_LABELS, b));
}

// "severity not published by this source" — the upstream API carries no
// severity, and inventing one is forbidden (rule 4).
function severityNotPublished() {
  return el("span", {
    class: "sev-none",
    title: "The upstream AKS CVE API publishes only a CVE id — no severity, CVSS, package or description. This site does not invent one.",
  }, "severity not published by this source");
}

/* ---------- time / staleness helpers (rule 3) ---------- */

function fmtDate(ts) { return (ts || "").slice(0, 10) || "\u2014"; }

// Prefer the feed's scan_age_days (a real integer since the PR #55 fix: the
// upstream Go RFC3339Nano timestamps carry 7-9 fractional digits, so the
// builder now parses them instead of returning null; observed range ~3-396
// days). When it is still null — a legitimate "age unknown" — fall back to
// computing from report_time client-side; return null only when neither is
// available, rendered as "age unknown" and NEVER as fresh/current.
function scanAgeDays(entry) {
  if (entry && typeof entry.scan_age_days === "number") return entry.scan_age_days;
  const rt = entry && entry.report_time;
  if (!rt) return null;
  const t = Date.parse(rt);
  if (isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86400000));
}

// Escalating staleness tiers. Real snapshots reach ~396 days (over a year), so
// the presentation must stay honest and legible at that magnitude, not just for
// a few days' skew (issue #40 F2). `unknown` is its own tier and is never
// treated as fresh.
function ageTier(d) {
  if (d == null) return "unknown";
  if (d <= 30) return "fresh";
  if (d <= 90) return "aging";
  if (d <= 270) return "stale";
  return "very_stale";
}

function ageText(entry) {
  const d = scanAgeDays(entry);
  if (d == null) return "scan age unknown";
  if (d === 0) return "scanned today";
  const base = d + (d === 1 ? " day old" : " days old");
  if (d >= 365) return base + " \u2014 over a year";
  if (d >= 182) return base + " \u2014 over 6 months";
  return base;
}

// A compact age for inline chips/labels where a full sentence does not fit.
function shortAge(entry) {
  const d = scanAgeDays(entry);
  if (d == null) return "age?";
  if (d === 0) return "today";
  return d + "d old";
}

// A coloured age badge whose weight escalates with the tier, so a year-old
// snapshot is visually unmissable rather than a subtle grey label.
function ageBadge(entry) {
  const d = scanAgeDays(entry);
  const tier = ageTier(d);
  const warn = tier === "stale" || tier === "very_stale" || tier === "unknown";
  return el("span", {
    class: "badge age age-" + tier,
    title: d == null
      ? "This version's scan timestamp could not be parsed, so its age is unknown. Treat its counts as unassessed for freshness — never as current."
      : "Scanned " + fmtDate(entry.report_time) + " (" + d + " day(s) ago). A CVE count only reflects the vulnerability database at scan time; an old scan under-reports CVEs disclosed since (issue #40 F2).",
  }, (warn ? "\u26A0 " : "") + ageText(entry));
}

// A prominent banner for a scan that is old (or of unknown age). This is the
// case issue #40 F2 exists for: a year-old snapshot under-reports newer CVEs, so
// absence of a CVE from it is especially weak evidence.
function staleBanner(v) {
  const tier = ageTier(scanAgeDays(v));
  if (tier === "fresh" || tier === "aging") return null;
  if (tier === "unknown") {
    return el("div", { class: "stale-banner stale-unknown" }, [
      el("strong", null, "\u26A0 Scan age unknown. "),
      "This version's report timestamp could not be parsed, so its freshness " +
        "cannot be assessed. Do not assume its counts are current; a missing CVE " +
        "here is not-observed, never fixed (issue #40 F2).",
    ]);
  }
  return el("div", { class: "stale-banner stale-" + tier }, [
    el("strong", null, "\u26A0 Old scan. "),
    "This snapshot is " + ageText(v) + " (scanned " + fmtDate(v.report_time) +
      "). Its CVE list reflects the vulnerability database as of that date and is " +
      "very likely missing CVEs disclosed since. For an old scan especially, " +
      "absence of a CVE is weak evidence — treat it as not-observed, never as " +
      "fixed or clean (issue #40 F2).",
  ]);
}

// The join key into image/index.json is the host-qualified repo EXACTLY as it
// appears in k8s/ and release/ documents (e.g.
// "mcr.microsoft.com/oss/kubernetes/kube-proxy"). PR feat/images-publish keys
// image/<slug>.json on that verbatim value so any repo from a k8s/release doc
// joins straight through — the host must NOT be stripped or normalised. im.image
// may carry a ":tag" suffix and is only a display/fallback, never the key.
function imageKey(im) {
  return (im && im.repo) || ((im && im.image) || "").split(":")[0];
}

// A provenance card, always rendered for a version (rule 3). `full` adds the
// image/CVE counts and the comparable_with cohort warning.
function provenanceCard(v, opts) {
  opts = opts || {};
  const dl = el("dl", { class: "kv" });
  dl.appendChild(el("dt", null, "Kubernetes version"));
  dl.appendChild(el("dd", null, el("span", { class: "mono" }, v.version || v.k8s_version)));
  dl.appendChild(el("dt", null, ["Basis", info(BASIS_HELP.k8s_snapshot)]));
  dl.appendChild(el("dd", null, basisBadge("k8s_snapshot")));
  dl.appendChild(el("dt", null, "Scanned"));
  dl.appendChild(el("dd", null, [fmtDate(v.report_time) + " ", ageBadge(v)]));
  dl.appendChild(el("dt", null, ["Cohort", info("Versions scanned on the same date share a cohort. Counts are ONLY comparable within a cohort — a version scanned earlier will look 'safer' purely because its scan is older, not because it is more secure (issue #40 F2).")]));
  dl.appendChild(el("dd", null, el("span", { class: "mono" }, v.cohort || fmtDate(v.report_time))));
  if (opts.counts) {
    dl.appendChild(el("dt", null, "Images"));
    dl.appendChild(el("dd", null, String(v.image_count)));
    dl.appendChild(el("dt", null, "Active CVEs"));
    dl.appendChild(el("dd", null, [String(v.cve_count) + " ", el("span", { class: "muted" }, "(no severity — "), severityNotPublished(), el("span", { class: "muted" }, ")")]));
  }
  const card = el("div", { class: "card provenance" }, [
    el("h3", null, "Scan provenance"), dl,
  ]);
  const comparable = v.comparable_with || [];
  const warn = el("div", { class: "cohort-warn" }, [
    el("strong", null, "\u26A0 Staleness warning. "),
    "These counts are only comparable with the " + comparable.length +
      " other version(s) scanned in the same cohort (" +
      (v.cohort || fmtDate(v.report_time)) + "). ",
    "Versions from a different cohort will look safer purely because their scan " +
      "is older and ran against an older vulnerability database — do not compare " +
      "raw counts across cohorts (issue #40 F2).",
    comparable.length
      ? el("details", { class: "comparable" }, [
          el("summary", null, "Comparable versions (" + comparable.length + ")"),
          el("div", { class: "chips" }, comparable.map((cv) =>
            el("a", { class: "chip", href: "#/" + encodeURIComponent(cv) }, cv))),
        ])
      : null,
  ]);
  return el("div", null, [card, staleBanner(v), warn]);
}

/* ---------- export helpers (Screen 2: round-trip into Excel) ---------- */

function neutralizeFormula(s) {
  // Prevent CSV/TSV formula (a.k.a. CSV) injection: a cell that begins with
  // = + - @ (or a control char a spreadsheet treats as a formula lead) is
  // prefixed with a single quote so Excel/Sheets render it as literal text.
  // Reachable now that user-pasted unrecognized input reaches the export.
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}
function csvEscape(v) {
  const s = neutralizeFormula(String(v == null ? "" : v));
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function toCSV(headers, rows) {
  return [headers].concat(rows).map((r) => r.map(csvEscape).join(",")).join("\r\n");
}
function tsvCell(v) { return neutralizeFormula(String(v == null ? "" : v).replace(/[\t\r\n]+/g, " ")); }
function toTSV(headers, rows) {
  return [headers].concat(rows).map((r) => r.map(tsvCell).join("\t")).join("\r\n");
}

function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: (mime || "text/plain") + ";charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(text, btn) {
  const ok = () => { if (btn) { const t = btn.textContent; btn.textContent = "Copied \u2713"; setTimeout(() => { btn.textContent = t; }, 1400); } };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      ok();
      return;
    }
  } catch (_e) { /* fall through to the textarea path */ }
  const ta = el("textarea", { style: "position:fixed;left:-9999px;top:0" });
  ta.value = text;
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try { document.execCommand("copy"); ok(); } catch (_e) { /* ignore */ }
  document.body.removeChild(ta);
}

/* ---------- Screen 1: front door (pick a Kubernetes version) ---------- */

function minorsMap() {
  const m = new Map();
  for (const v of state.index.k8s_versions) {
    (m.get(v.minor) || m.set(v.minor, []).get(v.minor)).push(v);
  }
  // Newest patch first within each minor (numeric compare on the patch part).
  for (const arr of m.values()) arr.sort((a, b) => cmpVersion(b.version, a.version));
  return m;
}

function cmpVersion(a, b) {
  const pa = (a || "").split(".").map(Number);
  const pb = (b || "").split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

function renderHome(opts) {
  opts = opts || {};
  const idx = state.index;
  const mmap = minorsMap();
  const minors = Array.from(mmap.keys()).sort((a, b) => cmpVersion(b, a));

  const minorSel = el("select", { id: "sel-minor", "aria-label": "Kubernetes minor version" },
    [el("option", { value: "" }, "Choose a minor…")].concat(
      minors.map((mn) => el("option", { value: mn }, mn + "  (" + mmap.get(mn).length + " patch scans)"))));
  const patchSel = el("select", { id: "sel-patch", "aria-label": "Kubernetes patch version", disabled: "disabled" },
    [el("option", { value: "" }, "Choose a minor first…")]);
  const notSure = el("label", { class: "not-sure" }, [
    el("input", { type: "checkbox", id: "sel-newest" }),
    " I'm not sure of my patch version — use the newest scanned patch",
  ]);
  const go = el("button", { class: "primary-btn", disabled: "disabled", id: "sel-go" }, "View this version \u2192");
  let chosen = null;

  const refreshPatch = () => {
    const mn = minorSel.value;
    patchSel.replaceChildren();
    if (!mn) { patchSel.disabled = true; patchSel.appendChild(el("option", { value: "" }, "Choose a minor first…")); go.disabled = true; return; }
    const list = mmap.get(mn);
    patchSel.disabled = false;
    patchSel.appendChild(el("option", { value: "" }, "Choose a patch…"));
    for (const v of list) {
      const stale = ageTier(scanAgeDays(v));
      const mark = (stale === "stale" || stale === "very_stale" || stale === "unknown") ? "  \u26A0" : "";
      patchSel.appendChild(el("option", { value: v.version },
        v.version + "  ·  scanned " + fmtDate(v.report_time) + " (" + ageText(v) + ")" + mark));
    }
    if (document.getElementById("sel-newest").checked) {
      patchSel.value = list[0].version;
    }
    syncGo();
  };
  const syncGo = () => {
    const newest = document.getElementById("sel-newest").checked;
    if (newest && minorSel.value) chosen = mmap.get(minorSel.value)[0].version;
    else chosen = patchSel.value || null;
    go.disabled = !chosen;
  };
  minorSel.addEventListener("change", refreshPatch);
  patchSel.addEventListener("change", syncGo);
  notSure.querySelector("input").addEventListener("change", () => {
    patchSel.disabled = document.getElementById("sel-newest").checked || !minorSel.value;
    refreshPatch();
  });
  go.addEventListener("click", () => { if (chosen) location.hash = "#/" + encodeURIComponent(chosen); });

  // Free-text guard: an unrecognised version is "not scanned", never "clean".
  const findInput = el("input", { id: "sel-find", type: "search", placeholder: "e.g. 1.33.11", autocomplete: "off", spellcheck: "false" });
  const findMsg = el("p", { class: "note", id: "sel-find-msg" }, "");
  const known = new Set(state.index.k8s_versions.map((v) => v.version));
  const doFind = () => {
    const q = findInput.value.trim();
    if (!q) { findMsg.textContent = ""; return; }
    if (known.has(q)) { location.hash = "#/" + encodeURIComponent(q); return; }
    findMsg.replaceChildren(el("strong", null, "Not scanned. "),
      document.createTextNode("Kubernetes " + q + " is not in this feed's scan index, so this site has no data for it. That is NOT the same as \u201Cno CVEs\u201D / \u201Cclean\u201D \u2014 it means not assessed. Pick a scanned version above."));
  };
  findInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doFind(); });

  const cohortList = idx.cohorts || {};
  const cohortRows = Object.keys(cohortList).sort().reverse().map((c) =>
    el("li", null, [el("span", { class: "mono" }, c), " — " + cohortList[c].length + " version(s)"]));

  const view = el("div", null, [
    el("p", { class: "intro" }, "Choose your Kubernetes version. Everything on this site is keyed on it — a CVE has no meaning without a version, and a real cluster runs one specific version, not \u201Can AKS release.\u201D"),
    el("div", { class: "card selector" }, [
      el("h3", null, "1 · Pick your Kubernetes version"),
      el("p", { class: "note" }, ["Run ", el("span", { class: "mono" }, "kubectl version"), " or ", el("span", { class: "mono" }, "az aks show --query kubernetesVersion"), " to find it."]),
      el("div", { class: "sel-grid" }, [
        el("div", { class: "field" }, [el("label", { for: "sel-minor" }, "Minor"), minorSel]),
        el("div", { class: "field" }, [el("label", { for: "sel-patch" }, "Patch"), patchSel]),
      ]),
      notSure,
      el("div", { class: "sel-actions" }, [go]),
      el("hr", { class: "soft" }),
      el("div", { class: "field" }, [
        el("label", { for: "sel-find" }, "…or type an exact version"),
        el("div", { class: "inline-find" }, [findInput, el("button", { class: "primary-btn ghost", onclick: doFind }, "Go")]),
      ]),
      findMsg,
    ]),
    opts.unknown
      ? el("div", { class: "error" }, "\u201C" + opts.unknown + "\u201D is not a recognised route or a scanned Kubernetes version.")
      : null,
    el("div", { class: "card" }, [
      el("h3", null, ["Why the Kubernetes version — and why scan cohorts matter", info("issue #40 F2")]),
      el("p", { class: "note" }, "The scanned versions below were captured at different times. A naive CVE count is INVERTED by this: an older scan reports fewer CVEs only because it ran against an older vulnerability database, not because that version is safer. Counts are only comparable within a cohort (a scan date)."),
      el("p", { class: "note" }, "Scan cohorts in this feed (newest first):"),
      el("ul", { class: "bullets" }, cohortRows),
    ]),
    el("p", { class: "note" }, [state.index.aks_releases ? state.index.aks_releases.length + " AKS release trains are also indexed. " : "", "See the ", el("a", { href: "#/help" }, "Help & glossary"), " page for how the two evidence axes differ and must never be blended."]),
  ]);
  $app().replaceChildren(view);
  setGeneratedFooter();
}

/* ---------- Screen 2: findings for a version (grouped by image) ---------- */

// cve -> [ {image, repo, tag} ] from a k8s document, and the per-image list.
function indexVersion(doc) {
  const byCve = new Map();
  for (const img of doc.images || []) {
    for (const cve of img.cves || []) {
      (byCve.get(cve) || byCve.set(cve, []).get(cve)).push(img);
    }
  }
  return byCve;
}

// Match anything that LOOKS like a CVE reference, so a malformed token can be
// REPORTED rather than silently dropped; plus a strict validator. A CVE id is
// CVE-<4-digit year>-<4-or-more digits>. Do NOT cap the digit run: real ids
// exceed 7 digits and truncating one produces a confident answer about a
// DIFFERENT CVE (the worst failure mode for a vulnerability tool).
const CVE_ISH_RE = /\bCVE[A-Z0-9._-]*/gi;
const CVE_EXACT_RE = /^CVE-\d{4}-\d{4,}$/;

// Returns { ids, unrecognized }. `ids` = unique valid upper-cased CVE ids in
// first-seen order. `unrecognized` = the user's own line text for any line that
// CONTAINED a CVE-like token we could not parse as a valid id — surfaced so a
// customer never silently loses a row. A line with NO CVE-like token (a bare
// binary path — expected spreadsheet noise) is deliberately NOT reported.
function parseCveList(raw) {
  const ids = [], unrecognized = [];
  const seenId = new Set(), seenBad = new Set();
  for (const line of (raw || "").split(/\r?\n/)) {
    const upper = line.toUpperCase();
    for (const tok of upper.match(CVE_ISH_RE) || []) {
      const t = tok.replace(/[._-]+$/, "");    // trim trailing separators
      if (CVE_EXACT_RE.test(t)) {
        if (!seenId.has(t)) { seenId.add(t); ids.push(t); }
      } else {
        const ctx = line.trim() || t;          // echo the user's own line back
        if (!seenBad.has(ctx)) { seenBad.add(ctx); unrecognized.push(ctx); }
      }
    }
  }
  return { ids: ids, unrecognized: unrecognized };
}

async function renderVersion(version, query) {
  $app().replaceChildren(el("p", { class: "loading" }, "Loading Kubernetes " + version + "\u2026"));
  const meta = (state.index.k8s_versions || []).find((v) => v.version === version);
  if (!meta) {
    $app().replaceChildren(el("div", null, [
      el("a", { class: "back", href: "#/" }, "\u2190 Choose a version"),
      el("div", { class: "error" }, [
        el("strong", null, "Not scanned. "),
        "Kubernetes " + version + " is not in this feed's scan index. This is \u201Cnot assessed,\u201D never \u201Cclean\u201D — there is no scan report to read for it.",
      ]),
    ]));
    return;
  }
  let doc;
  try { doc = await loadK8s(version); }
  catch (e) {
    $app().replaceChildren(el("div", null, [
      el("a", { class: "back", href: "#/" }, "\u2190 Choose a version"),
      el("div", { class: "error" }, "Could not load the scan report for " + version + " (" + e.message + ")."),
    ]));
    return;
  }
  const byCve = indexVersion(doc);
  if (state.bulk.version !== version) state.bulk = { raw: "", results: null, version: version };

  const view = el("div", null, [
    el("a", { class: "back", href: "#/" }, "\u2190 Choose a version"),
    el("div", { class: "detail-head" }, [el("h2", null, "Kubernetes " + version)]),
    provenanceCard(meta, { counts: true }),
    bulkTriageCard(doc, byCve),
    singleCveCard(version),
    imageGroupCard(doc, version, query),
  ]);
  $app().replaceChildren(view);
  setGeneratedFooter();
  const focus = query && query.get("q");
  if (focus) { const box = document.getElementById("repo-filter"); if (box) { box.value = focus; box.dispatchEvent(new Event("input")); } }
}

function bulkTriageCard(doc, byCve) {
  const version = doc.k8s_version;
  const ta = el("textarea", {
    id: "bulk-in", rows: "6", spellcheck: "false",
    placeholder: "Paste a column of CVE ids from your spreadsheet, e.g.\nCVE-2025-40292\nCVE-2024-12133\n…",
  });
  ta.value = state.bulk.raw || "";
  const out = el("div", { id: "bulk-out" });

  const render = () => {
    const { ids, unrecognized } = parseCveList(ta.value);
    state.bulk.raw = ta.value;
    if (!ids.length && !unrecognized.length) { out.replaceChildren(el("p", { class: "note" }, "No CVE ids found in the pasted text yet.")); state.bulk.results = null; return; }
    const rows = ids.map((id) => {
      const hits = byCve.get(id) || [];
      // Distinguish "active" from "not observed in this scan" honestly: an
      // absence is not a proof of safety (rule 2).
      return {
        id: id,
        observed: hits.length > 0,
        state: hits.length ? "active" : "not_observed",
        images: hits.map((h) => h.image),
      };
    });
    state.bulk.results = { version: version, rows: rows, unrecognized: unrecognized, report_time: doc.report_time, cohort: doc.cohort };
    const activeN = rows.filter((r) => r.observed).length;
    const body = el("tbody", null, rows.map((r) => el("tr", null, [
      el("td", { class: "mono" }, el("a", { href: "#/" + encodeURIComponent(version) + "/" + encodeURIComponent(r.id) }, r.id)),
      el("td", null, r.observed
        ? el("span", { class: "badge img-st img-st-active", title: PRESENTATION_HELP.active }, "Active")
        : el("span", { class: "badge img-st img-st-not_observed", title: "This CVE is not in " + version + "'s scan report. That means NOT OBSERVED in this scan — not proof the version is unaffected (issue #40, rule: absence \u2260 not affected)." }, "Not observed in this scan")),
      el("td", null, String(r.images.length)),
      el("td", { class: "mono small" }, r.images.length ? r.images.join("\n") : "\u2014"),
    ])));
    const table = ids.length ? el("div", { class: "table-wrap" }, el("table", null, [
      el("thead", null, el("tr", null, [
        el("th", null, "CVE"),
        el("th", null, ["Status on " + version, info("Active = the scanner reports it on \u2265 1 image on this version. Not observed = absent from this scan; NOT a proof of safety.")]),
        el("th", null, "Images"),
        el("th", null, "Image list"),
      ])),
      body,
    ])) : null;
    const unrecPanel = unrecognized.length ? el("div", { class: "bulk-unrec" }, [
      el("strong", null, "\u26A0 " + unrecognized.length + " line(s) could not be read as CVE ids and were NOT checked:"),
      el("ul", { class: "unrec-list" }, unrecognized.slice(0, 50).map((u) => el("li", { class: "mono small" }, u))),
      unrecognized.length > 50 ? el("p", { class: "note" }, "\u2026and " + (unrecognized.length - 50) + " more.") : null,
      el("p", { class: "note" }, "A line is flagged here only when it contains a CVE-like token we could not parse (e.g. a truncated or malformed id). These are also appended to the CSV/TSV export (status = unrecognized_input) so nothing is lost when you paste it back into Excel."),
    ]) : null;
    const summaryKids = [
      el("strong", null, ids.length + " CVE id(s) checked"),
      " against Kubernetes " + version + " (scanned " + fmtDate(doc.report_time) + "): ",
      el("strong", { class: "count-active" }, activeN + " active"),
      ", " + (ids.length - activeN) + " not observed in this scan.",
    ];
    if (unrecognized.length) {
      summaryKids.push(" ");
      summaryKids.push(el("strong", { class: "count-unrec" }, "\u26A0 " + unrecognized.length + " line(s) NOT recognised and NOT checked (listed below)."));
    }
    out.replaceChildren(
      el("p", { class: "result-summary" }, summaryKids),
      exportBar(version, rows, doc, unrecognized),
      unrecPanel,
      table,
    );
  };

  ta.addEventListener("input", render);
  const runBtn = el("button", { class: "primary-btn", onclick: render }, "Check these CVEs");
  const clearBtn = el("button", { class: "ghost-btn", onclick: () => { ta.value = ""; state.bulk = { raw: "", results: null, version: version }; render(); } }, "Clear");

  const card = el("div", { class: "card bulk" }, [
    el("h3", null, ["Bulk CVE triage", info("Paste a whole column of CVE ids from a spreadsheet and get the per-image status for each on this Kubernetes version. Copy the result back as TSV, or download CSV — both open cleanly in Excel.")]),
    el("p", { class: "note" }, "Your primary workflow: you have a spreadsheet of CVEs and you know your Kubernetes version. Paste the ids; get a filled-in status column back."),
    ta,
    el("div", { class: "sel-actions" }, [runBtn, clearBtn]),
    out,
  ]);
  if (state.bulk.raw) render();
  else out.replaceChildren(el("p", { class: "note" }, "Paste CVE ids above, then Check."));
  return card;
}

function exportBar(version, rows, doc, unrecognized) {
  const headers = ["cve", "status", "image_count", "images", "k8s_version", "report_time", "cohort", "basis", "source_url"];
  const table = rows.map((r) => [
    r.id,
    r.observed ? "active" : "not_observed_in_this_scan",
    r.images.length,
    r.images.join("; "),
    version,
    doc.report_time || "",
    doc.cohort || "",
    "k8s_snapshot",
    doc.source_url || "",
  ]);
  // Append the unrecognized lines as their own rows so a customer who pastes the
  // export back into Excel never silently loses input (fix #1 / rule 2).
  for (const u of (unrecognized || [])) {
    table.push([u, "unrecognized_input", "", "", version, doc.report_time || "", doc.cohort || "", "k8s_snapshot", doc.source_url || ""]);
  }
  const csv = toCSV(headers, table);
  const tsv = toTSV(headers, table);
  const copyBtn = el("button", { class: "ghost-btn" }, "Copy as TSV (paste into Excel)");
  copyBtn.addEventListener("click", () => copyText(tsv, copyBtn));
  const dlBtn = el("button", { class: "ghost-btn", onclick: () => downloadText("cve-status-" + version + ".csv", csv, "text/csv") }, "Download CSV");
  const unrecN = (unrecognized || []).length;
  return el("div", { class: "export-bar" }, [copyBtn, dlBtn,
    el("span", { class: "note" }, "Columns: cve, status, image_count, images, k8s_version, report_time, cohort, basis, source_url."
      + (unrecN ? " Includes " + unrecN + " unrecognised input line(s) as status=unrecognized_input." : ""))]);
}

function singleCveCard(version) {
  const inp = el("input", { id: "single-cve", type: "search", placeholder: "CVE-2026-1234", autocomplete: "off", spellcheck: "false" });
  const go = () => {
    const { ids } = parseCveList(inp.value);
    if (ids.length) location.hash = "#/" + encodeURIComponent(version) + "/" + encodeURIComponent(ids[0]);
  };
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  return el("div", { class: "card" }, [
    el("h3", null, "Open one CVE in detail"),
    el("div", { class: "inline-find" }, [inp, el("button", { class: "primary-btn ghost", onclick: go }, "Open \u2192")]),
    el("p", { class: "note" }, "Opens the per-image state table, resolution paths and provenance for this CVE on " + version + "."),
  ]);
}

function imageGroupCard(doc, version, query) {
  const images = doc.images || [];    // pre-sorted by CVE count desc (issue #40 F7)
  const filter = el("input", { id: "repo-filter", type: "search", placeholder: "Filter by image repo, e.g. istio", autocomplete: "off", spellcheck: "false" });
  const listWrap = el("div", { id: "image-list" });

  const draw = () => {
    const q = (filter.value || "").trim().toLowerCase();
    const shown = images.filter((im) => !q || (im.repo || "").toLowerCase().includes(q) || (im.image || "").toLowerCase().includes(q));
    if (!shown.length) { listWrap.replaceChildren(el("p", { class: "empty" }, "No images match that filter.")); return; }
    listWrap.replaceChildren(el("ul", { class: "image-groups" }, shown.map((im) => {
      const det = el("details", { class: "image-group" }, [
        el("summary", null, [
          el("span", { class: "img-count" }, String(im.cve_count)),
          el("span", { class: "img-count-label" }, "CVEs"),
          el("span", { class: "mono img-ref" }, im.image || (im.repo + (im.tag ? ":" + im.tag : ""))),
        ]),
      ]);
      // Lazily fill the CVE list when a group is first expanded (some images
      // carry 2,500+ CVEs — never build them all up front).
      let filled = false;
      det.addEventListener("toggle", () => {
        if (!det.open || filled) return;
        filled = true;
        const cves = im.cves || [];
        det.appendChild(el("div", { class: "cve-chip-wrap" },
          cves.length
            ? cves.map((c) => el("a", { class: "chip", href: "#/" + encodeURIComponent(version) + "/" + encodeURIComponent(c) }, c))
            : el("span", { class: "note" }, "No active CVEs reported for this image on this scan.")));
      });
      return el("li", null, det);
    })));
  };
  filter.addEventListener("input", draw);
  draw();

  return el("div", { class: "card" }, [
    el("h3", null, ["Findings grouped by image", info("A single image can dominate a version's total (issue #40 F7), so the count is led by the per-image distribution, not one scalar. The feed pre-sorts images by CVE count, descending.")]),
    el("p", { class: "note" }, "Every image running on " + version + ", most-vulnerable first. Expand an image to see and open its CVEs. No severity is shown because the upstream source publishes none (rule 4)."),
    el("div", { class: "field" }, [el("label", { for: "repo-filter" }, "Filter images"), filter]),
    listWrap,
  ]);
}

/* ---------- Screen 3: CVE detail  #/<version>/<CVE> ---------- */

async function renderCve(version, cveRaw) {
  const cve = (cveRaw || "").toUpperCase();
  $app().replaceChildren(el("p", { class: "loading" }, "Loading " + cve + " on " + version + "\u2026"));
  const meta = (state.index.k8s_versions || []).find((v) => v.version === version);
  let k8sDoc = null, cveDoc = null, cveErr = null;
  try { k8sDoc = meta ? await loadK8s(version) : null; } catch (_e) { k8sDoc = null; }
  try { cveDoc = await loadCve(cve); } catch (e) { cveErr = e; }

  const head = el("div", null, [
    el("a", { class: "back", href: "#/" + encodeURIComponent(version) }, "\u2190 Back to " + version),
    el("div", { class: "detail-head" }, [
      el("h2", null, cve),
      el("span", { class: "mono muted" }, "on Kubernetes " + version),
    ]),
    el("p", { class: "note" }, ["A CVE has no meaning without a version — this page is scoped to ", el("span", { class: "mono" }, cve), " on ", el("span", { class: "mono" }, version), ". ", severityNotPublished(), "."]),
  ]);

  if (!meta) {
    $app().replaceChildren(el("div", null, [head,
      el("div", { class: "error" }, [el("strong", null, "Version not scanned. "),
        "Kubernetes " + version + " has no scan report in this feed, so this CVE's state on it is NOT ASSESSED — never assume clean."])]));
    return;
  }

  const blockA = renderCveImageTable(version, cve, k8sDoc, cveDoc);
  const provBlock = renderCveProvenance(version, meta, cveDoc, cveErr);

  // Screen 3 renders per-version status, so the freshness of THAT scan must be
  // visible here too (finding #5 / rule 3) — not only on the version front door.
  const ageStrip = el("p", { class: "scan-strip" }, [
    "Kubernetes " + version + " was scanned ", fmtDate(meta.report_time) + " ", ageBadge(meta),
    " · cohort ", el("span", { class: "mono" }, meta.cohort || fmtDate(meta.report_time)),
  ]);

  const container = el("div", null, [head, ageStrip, staleBanner(meta), blockA, el("div", { id: "resolution-paths" }, el("p", { class: "loading" }, "Computing resolution paths\u2026")), provBlock]);
  $app().replaceChildren(container);
  setGeneratedFooter();

  // Resolution paths (Path B needs the release chain) are computed off the
  // first-paint path, then swapped in — a slow/absent release axis never blocks
  // the state table.
  renderResolutionPaths(version, cve, cveDoc).then((node) => {
    const slot = document.getElementById("resolution-paths");
    if (slot) slot.replaceChildren(node);
  });
}

// Block A — per-image state on THIS version. Active images come from the k8s
// snapshot; every state is labelled and no absence is rendered as green.
function renderCveImageTable(version, cve, k8sDoc, cveDoc) {
  let activeImages = [];
  if (k8sDoc) {
    activeImages = (k8sDoc.images || []).filter((im) => (im.cves || []).includes(cve));
  } else if (cveDoc) {
    activeImages = (cveDoc.k8s || []).filter((e) => e.k8s_version === version)
      .map((e) => ({ image: e.image, repo: e.repo, tag: e.tag, cves: [cve] }));
  }
  const totalImages = k8sDoc ? (k8sDoc.images || []).length : null;

  const rows = activeImages.map((im) => el("tr", null, [
    el("td", { class: "mono" }, el("a", { href: "#/image/" + encodeURIComponent(imageKey(im)) }, im.repo || im.image)),
    el("td", { class: "mono" }, im.tag || "\u2014"),
    el("td", null, stateBadge("active")),
    el("td", null, basisBadge("k8s_snapshot")),
  ]));

  const table = activeImages.length
    ? el("div", { class: "table-wrap" }, el("table", null, [
        el("thead", null, el("tr", null, [
          el("th", null, "Image"),
          el("th", null, "Tag on " + version),
          el("th", null, ["State", info(PRESENTATION_HELP.active)]),
          el("th", null, ["Evidence axis", info(BASIS_HELP.k8s_snapshot)]),
        ])),
        el("tbody", null, rows),
      ]))
    : el("p", { class: "note" }, k8sDoc
        ? "No image on " + version + " reports this CVE in the current scan."
        : "The scan report for this version could not be loaded; showing the CVE document's view instead.");

  const note = totalImages != null
    ? el("p", { class: "note" }, [
        el("strong", null, activeImages.length + " of " + totalImages + " images"),
        " scanned on " + version + " report " + cve + " (state ", stateBadge("active"),
        "). The remaining images do NOT report it in this scan — that is ",
        el("strong", null, "not observed"),
        ", not a proof of ", stateBadge("not_affected"), " (rule 2). An image that does not run on this version is ", stateBadge("not_present"), ".",
      ])
    : null;

  return el("div", { class: "card" }, [
    el("h3", null, ["Per-image state on " + version, info("Sourced only from the frozen Kubernetes snapshot for this version (basis k8s_snapshot). Never blended with the AKS release axis below.")]),
    table,
    note,
  ]);
}

// Block B — resolution paths. Path A from the Kubernetes axis (cve doc + index),
// Path B from the AKS release chain (first-fix records).
async function renderResolutionPaths(version, cve, cveDoc) {
  const meta = (state.index.k8s_versions || []).find((v) => v.version === version);
  const curMinor = meta ? meta.minor : "";

  // Path A — upgrade Kubernetes. "Affected" versions are exactly those the CVE
  // doc lists on the k8s axis; any scanned version NOT in that set is "not
  // reported" (never "proven clean").
  const affectedVersions = new Set((cveDoc && cveDoc.k8s || []).map((e) => e.k8s_version));
  const affectedMinors = new Set((cveDoc && cveDoc.affected_minors) || []);
  const allScanned = (state.index.k8s_versions || []);
  const newerClear = allScanned.filter((v) =>
    !affectedVersions.has(v.version) && cmpVersion(v.version, version) > 0);
  // Prefer versions in the same cohort (comparable), then newer minors.
  const sameCohort = meta ? new Set([version].concat(meta.comparable_with || [])) : new Set();
  newerClear.sort((a, b) => cmpVersion(a.version, b.version));

  let pathA;
  if (!cveDoc) {
    pathA = pathBlock("A", "Upgrade Kubernetes", "unknown",
      "This CVE has no per-CVE document in this feed build, so an upgrade path cannot be computed. Treat as unknown, not unavailable.");
  } else if (newerClear.length) {
    const chips = newerClear.slice(0, 24).map((v) => {
      const comparable = sameCohort.has(v.version);
      const tier = ageTier(scanAgeDays(v));
      const oldish = tier === "stale" || tier === "very_stale" || tier === "unknown";
      // Surface staleness + cross-cohort in VISIBLE text, not only title= — a
      // tooltip is invisible to touch, many screen readers, and text scrapers,
      // so a 235-day cross-cohort chip must not look "clean" (finding #4).
      const meta2 = [];
      if (oldish) meta2.push(shortAge(v));
      if (!comparable) meta2.push("\u26A0 diff cohort");
      return el("a", {
        class: "chip" + (comparable ? " chip-strong" : "") + (oldish ? " chip-stale" : ""),
        href: "#/" + encodeURIComponent(v.version),
        title: "Scanned " + fmtDate(v.report_time) + " (" + ageText(v) + ")" + (comparable ? " — same scan cohort, directly comparable" : " — different cohort; compare with care"),
      }, meta2.length ? [v.version, el("span", { class: "chip-meta" }, " · " + meta2.join(" · "))] : v.version);
    });
    pathA = pathBlock("A", "Upgrade Kubernetes", "available", null, [
      el("p", null, ["Newer scanned Kubernetes versions that do ", el("strong", null, "not report"), " " + cve + ":"]),
      el("div", { class: "chips" }, chips),
      newerClear.length > 24 ? el("p", { class: "note" }, "…and " + (newerClear.length - 24) + " more.") : null,
      el("p", { class: "note" }, ["Bold chips share this version's scan cohort, so the comparison is direct; \u201C\u26A0 diff cohort\u201D chips were scanned on a different date and are NOT directly comparable (an older scan looks safer for free). \u201CNot reported\u201D means the CVE is absent from that version's scan (issue #40 F8) \u2014 a real, available remediation signal, but confirm the same image still ships there before relying on it; absence is not a guarantee (rule 2)."]),
    ]);
  } else {
    pathA = pathBlock("A", "Upgrade Kubernetes", "pending", affectedMinors.size
      ? "Every scanned Kubernetes version newer than " + version + " still reports this CVE (affected minors: " + Array.from(affectedMinors).sort().join(", ") + "). Upgrading Kubernetes alone does not clear it in this scan set."
      : "No newer scanned Kubernetes version clears this CVE in this feed build.");
  }

  // Path B — wait for an AKS release. Uses the release chain's first-fix records.
  const relEntries = (cveDoc && cveDoc.releases) || [];
  const anyMapped = relEntries.some((r) => (r.k8s_attribution || {}).state !== "k8s_unmapped");
  const anyUnmapped = relEntries.some((r) => (r.k8s_attribution || {}).state === "k8s_unmapped");
  let pathB;
  const ffIndex = await loadFirstFixIndex();
  const fixes = (ffIndex && ffIndex[cve]) || [];
  const relLoad = state.releaseLoad || { failed: 0, total: 0 };
  // A failed release-doc fetch must be distinguishable from "no fix recorded":
  // an incomplete chain cannot support any negative conclusion (rule 2).
  const loadWarn = relLoad.failed
    ? el("p", { class: "note load-error" }, [
        el("strong", null, "\u26A0 Release history could not be fully loaded "),
        "(" + relLoad.failed + " of " + relLoad.total + " AKS release document(s) failed to fetch). ",
        "This is a load error, NOT a statement that no fix exists — treat any \u201Cno fix recorded\u201D below as unverified until the release history loads.",
      ])
    : null;
  if (fixes.length) {
    const first = fixes[0];
    const targets = fixes.map((f) => f.pod_namespace + "/" + f.container_name);
    const uniqTargets = Array.from(new Set(targets));
    pathB = pathBlock("B", "Wait for a new AKS release", "available", null, [
      el("p", null, [
        "First mitigated in AKS release ", el("span", { class: "mono strong" }, first.release),
        " for ", el("span", { class: "mono" }, uniqTargets.slice(0, 4).join(", ")),
        uniqTargets.length > 4 ? " (+" + (uniqTargets.length - 4) + " more)" : "",
        " ", el("span", { class: "badge ffsrc ffsrc-" + first.first_fixed_source, title: FIRST_FIXED_SOURCE_HELP[first.first_fixed_source] || "" }, labelOf(FIRST_FIXED_SOURCE_LABELS, first.first_fixed_source)),
      ]),
      // Release-axis freshness: this "fix" comes from a release scan that can be
      // a year old, so its age must be visible (finding #2 / issue #40 F2).
      first.report_time ? el("p", { class: "note" }, ["That release was scanned ", fmtDate(first.report_time) + " ", ageBadge({ report_time: first.report_time, scan_age_days: first.scan_age_days }), ". The fix is only as current as this release-history scan."]) : null,
      anyUnmapped ? el("p", { class: "note" }, ["Some occurrences of this CVE are on images ", stateBadge("unknown_not_tracked"), " — not in the AKS release train, so their fix history is unavailable (issue #40 F5). \u201CFix history not tracked\u201D is not \u201Cnot fixed.\u201D"]) : null,
      el("p", { class: "note" }, "This is the AKS release-history axis (basis release_history) — continuously rescanned and NOT blended with the frozen Kubernetes snapshot above. The two can legitimately disagree (issue #40 F6)."),
    ]);
  } else if (relEntries.length && anyMapped) {
    pathB = pathBlock("B", "Wait for a new AKS release", relLoad.failed ? "unknown" : "pending", null, [
      loadWarn,
      el("p", null, relLoad.failed
        ? "This CVE appears on AKS-release images, but the release history could not be fully loaded (see above), so whether a fix has shipped cannot be determined here."
        : "This CVE appears on AKS-release images but no first-fix has been recorded across the release chain yet — nothing to do but wait; no fix ETA is published by the source."),
      el("div", { class: "chips" }, relEntries.slice(0, 8).map((r) => el("span", { class: "chip", title: labelOf(ATTRIBUTION_LABELS, (r.k8s_attribution || {}).state) }, r.release + " · " + r.pod_namespace + "/" + r.container_name))),
    ]);
  } else if (anyUnmapped) {
    pathB = pathBlock("B", "Wait for a new AKS release", "unknown", null, [
      loadWarn,
      el("p", null, ["This CVE's only AKS-release occurrences are on images ", stateBadge("unknown_not_tracked"), " — not tracked in the AKS release train, so \u201Cwhich AKS release fixes it\u201D cannot be answered (issue #40 F5). This is unknown, not \u201Cnot fixed.\u201D"]),
    ]);
  } else if (relLoad.failed) {
    // No release evidence AND the fetch failed: this is a load error, not a
    // finding of "no fix" (finding #3).
    pathB = pathBlock("B", "Wait for a new AKS release", "unknown", null, [loadWarn]);
  } else {
    pathB = pathBlock("B", "Wait for a new AKS release", "unknown",
      "This CVE does not appear in any AKS release report in this feed build, so its fix history is unavailable.");
  }

  return el("div", { class: "card" }, [
    el("h3", null, ["Resolution paths", info("The two questions a customer with a finding actually has: can I fix this by upgrading Kubernetes, or must I wait for a new AKS release?")]),
    pathA,
    pathB,
  ]);
}

function pathBlock(letter, title, status, text, children) {
  const badge = {
    available: ["\u2705 available", "path-ok"],
    pending: ["\u23F3 pending", "path-pending"],
    unknown: ["\u2753 unknown", "path-unknown"],
  }[status] || ["\u2014", "path-unknown"];
  return el("div", { class: "path " + badge[1] }, [
    el("div", { class: "path-head" }, [
      el("span", { class: "path-title" }, "Path " + letter + " — " + title),
      el("span", { class: "path-status" }, badge[0]),
    ]),
    text ? el("p", { class: "note" }, text) : null,
  ].concat(children || []));
}

// Block C — provenance, always rendered (rule 3 + honest sourcing).
function renderCveProvenance(version, meta, cveDoc, cveErr) {
  const rows = [];
  if (meta && meta.source_url) rows.push(["Kubernetes snapshot", meta.source_url, meta.report_time || "", "k8s_snapshot", { report_time: meta.report_time, scan_age_days: meta.scan_age_days }]);
  const relSet = new Map();
  for (const r of (cveDoc && cveDoc.releases) || []) {
    if (r.source_url && !relSet.has(r.source_url)) relSet.set(r.source_url, { rel: r.release, report_time: r.report_time, scan_age_days: r.scan_age_days });
  }
  for (const [url, r] of relSet) rows.push(["AKS release " + r.rel, url, r.report_time || "", "release_history", { report_time: r.report_time, scan_age_days: r.scan_age_days }]);

  const list = el("ul", { class: "ref-list" }, rows.map(([label, url, date, basis, ageEntry]) =>
    el("li", null, [
      basisBadge(basis), " " + label + ": ",
      isExternal(url) ? el("a", { href: url, target: "_blank", rel: "noopener" }, url) : el("span", { class: "mono" }, url),
      date ? el("span", { class: "muted" }, " (" + fmtDate(date) + ") ") : null,
      ageEntry && ageEntry.report_time ? ageBadge(ageEntry) : null,
    ])));

  return el("div", { class: "card" }, [
    el("h3", null, "Provenance"),
    cveErr ? el("p", { class: "note" }, "Per-CVE document unavailable (" + cveErr.message + "); showing snapshot provenance only.") : null,
    rows.length ? list : el("p", { class: "note" }, "No source URLs available for this CVE in this feed build."),
    el("p", { class: "note" }, "Derived: first-fix computed by diffing active_cves across the AKS release chain and cross-checked against the upstream mitigated list (issue #40 F6). The Kubernetes snapshot and release-history axes are shown separately and never merged."),
  ]);
}

/* ---------- Screen 4: image detail  #/image/<repo> ---------- */

async function renderImage(repoRaw) {
  const repo = repoRaw || "";
  $app().replaceChildren(el("p", { class: "loading" }, "Loading image " + repo + "\u2026"));
  const head = el("div", null, [
    el("a", { class: "back", href: "#/" }, "\u2190 Choose a version"),
    el("div", { class: "detail-head" }, [el("h2", { class: "mono" }, repo || "(image)")]),
  ]);

  const idx = await loadImageIndex();
  if (idx === null) {
    // Graceful degradation: per-image documents are a separate feed family that
    // may not be present in this build (they ship with PR feat/images-publish).
    $app().replaceChildren(el("div", null, [head, el("div", { class: "card notice" }, [
      el("h3", null, "Per-image documents are not present in this feed build"),
      el("p", { class: "note" }, ["The image detail screen is driven by ", el("span", { class: "mono" }, "image/index.json"), " and ", el("span", { class: "mono" }, "image/<slug>.json"), ", an optional feed family that this build does not publish (the images feed can deploy ahead of that family). Nothing is broken — there is simply no per-image document to show yet."]),
      el("p", { class: "note" }, ["You can still see this image's CVEs per Kubernetes version from any ", el("a", { href: "#/" }, "version's findings"), " page."]),
    ])]));
    return;
  }
  const items = (idx && idx.items) || [];
  // Resolve the host-qualified repo verbatim through image/index.json. `repo`
  // arrives from the hash unchanged (host included), and image/index.json keys
  // its entries on that same host-qualified value — never guess a filename.
  const entry = items.find((it) => it.name === repo);
  if (!entry) {
    $app().replaceChildren(el("div", null, [head, el("div", { class: "card notice" }, [
      el("h3", null, "No per-image document for this repository"),
      el("p", { class: "note" }, ["The image index does not list ", el("span", { class: "mono" }, repo), ". It is resolved through ", el("span", { class: "mono" }, "image/index.json"), " (filenames are never guessed), and this repo is not in it."]),
    ])]));
    return;
  }
  let doc;
  try { doc = await loadImageDoc(entry.file); }
  catch (e) {
    $app().replaceChildren(el("div", null, [head, el("div", { class: "error" }, "Could not load the per-image document (" + e.message + ").")]));
    return;
  }
  renderImageDoc(head, doc);
}

function renderImageDoc(head, doc) {
  const k8sRows = (doc.k8s || []).slice().sort((a, b) => cmpVersion(b.k8s_version, a.k8s_version)).map((e) =>
    el("tr", null, [
      el("td", { class: "mono" }, el("a", { href: "#/" + encodeURIComponent(e.k8s_version) }, e.k8s_version)),
      el("td", { class: "mono" }, e.tag || "\u2014"),
      el("td", null, String(e.cve_count != null ? e.cve_count : (e.cves || []).length)),
      el("td", null, [fmtDate(e.report_time) + " ", ageBadge(e)]),
    ]));
  const k8sCard = el("div", { class: "card" }, [
    el("h3", null, ["On which Kubernetes versions", info(BASIS_HELP.k8s_snapshot)]),
    basisBadge("k8s_snapshot"),
    (doc.k8s || []).length
      ? el("div", { class: "table-wrap" }, el("table", null, [
          el("thead", null, el("tr", null, [el("th", null, "K8s version"), el("th", null, "Tag"), el("th", null, "CVEs"), el("th", null, "Scanned")])),
          el("tbody", null, k8sRows)]))
      : el("p", { class: "note" }, "This image is not present in any frozen Kubernetes snapshot."),
  ]);

  const relRows = (doc.releases || []).map((e) =>
    el("tr", null, [
      el("td", { class: "mono" }, e.release),
      el("td", { class: "mono" }, e.tag || "\u2014"),
      el("td", { class: "mono small" }, (e.pod_namespace || "") + "/" + (e.container_name || "")),
      el("td", null, String(e.active_cve_count != null ? e.active_cve_count : "\u2014")),
      el("td", null, attrBadge((e.k8s_attribution || {}).state)),
      el("td", null, e.report_time ? [fmtDate(e.report_time) + " ", ageBadge(e)] : ageBadge(e)),
    ]));
  const relCard = el("div", { class: "card" }, [
    el("h3", null, ["In which AKS releases", info(BASIS_HELP.release_history)]),
    basisBadge("release_history"),
    (doc.releases || []).length
      ? el("div", { class: "table-wrap" }, el("table", null, [
          el("thead", null, el("tr", null, [el("th", null, "Release"), el("th", null, "Tag"), el("th", null, "Target"), el("th", null, "Active CVEs"), el("th", null, "Attribution"), el("th", null, ["Scanned", info("The AKS release axis is continuously rescanned; this is when THIS release's scan ran. An old release scan under-reports newer CVEs exactly like an old k8s snapshot (issue #40 F2).")])])),
          el("tbody", null, relRows)]))
      : el("p", { class: "note" }, "This image is not tracked in any AKS release report."),
  ]);

  const summary = el("div", { class: "card" }, [
    el("h3", null, "Summary"),
    (() => {
      const dl = el("dl", { class: "kv" });
      dl.appendChild(el("dt", null, "Repository")); dl.appendChild(el("dd", null, el("span", { class: "mono" }, doc.repo || "\u2014")));
      dl.appendChild(el("dt", null, "Tags")); dl.appendChild(el("dd", null, (doc.tags || []).length ? el("span", { class: "mono small" }, (doc.tags || []).join(", ")) : "\u2014"));
      dl.appendChild(el("dt", null, "K8s versions")); dl.appendChild(el("dd", null, String(doc.k8s_version_count != null ? doc.k8s_version_count : (doc.k8s || []).length)));
      dl.appendChild(el("dt", null, "AKS releases")); dl.appendChild(el("dd", null, String(doc.release_count != null ? doc.release_count : (doc.releases || []).length)));
      dl.appendChild(el("dt", null, "Distinct CVEs")); dl.appendChild(el("dd", null, [String(doc.cve_count != null ? doc.cve_count : (doc.cves || []).length) + " ", severityNotPublished()]));
      return dl;
    })(),
  ]);

  $app().replaceChildren(el("div", null, [head, summary, k8sCard, relCard]));
  setGeneratedFooter();
}

/* ---------- Screen 5: help / glossary ---------- */

function glossarySection(title, help, labels, helps, counts, shares, total) {
  const rows = Object.keys(labels).map((k) => {
    const kids = [el("span", { class: "gloss-name" }, labels[k]), el("code", null, k)];
    if (counts && typeof counts[k] === "number") {
      const share = shares && typeof shares[k] === "number" ? " · " + Math.round(shares[k] * 100) + "%" : "";
      kids.push(el("span", { class: "gloss-count muted" }, counts[k] + (total ? "/" + total : "") + share));
    }
    return el("div", { class: "gloss-row" }, [
      el("div", { class: "gloss-key" }, kids),
      el("p", null, helps[k] || ""),
    ]);
  });
  return el("div", null, [el("h3", null, title), help ? el("p", { class: "note" }, help) : null, el("div", { class: "glossary" }, rows)]);
}

function renderHelp() {
  const g = state.glossary.data || {};
  const attr = g.attribution || {};
  const ff = g.first_fixed_source || {};
  const ps = g.presentation_state || {};

  const view = el("div", { class: "help" }, [
    el("a", { class: "back", href: "#/" }, "\u2190 Choose a version"),
    el("h2", null, "Help & glossary"),
    el("p", { class: "note" }, ["This site reports which CVEs the scanner sees on the ", el("strong", null, "container images"), " AKS runs on your cluster — control plane, addons, CSI drivers, service mesh and Arc agents — keyed on your ", el("strong", null, "Kubernetes version"), ". It is a community project, not an official Microsoft feed."]),

    el("h3", null, "The number one way to misread this data: scan staleness"),
    el("p", { class: "note" }, "Different Kubernetes versions were scanned months apart. A naive CVE count is INVERTED by this: an older scan reports fewer CVEs only because it ran against an older vulnerability database, not because that version is safer. Every version carries its scan date, age and cohort, and comparisons across cohorts are warned about. Never conclude \u201Cfewer CVEs = safer\u201D across scan dates (issue #40 F2)."),

    el("h3", null, "Two evidence axes — never blended"),
    el("p", { class: "note" }, "A finding comes from one of two axes, which are different evidence and may legitimately disagree. This site always labels which axis a row is from and never merges them into one number or table."),
    glossarySection("Evidence axes", null, BASIS_LABELS, BASIS_HELP),

    el("h3", null, "Severity"),
    el("p", { class: "note" }, ["The upstream AKS CVE API publishes only a CVE id — no severity, CVSS, package or description. This site shows \u201C", severityNotPublished(), "\u201D rather than inventing one (issue #40 F3/F4)."]),

    glossarySection("Per-image CVE states", "The state of a (Kubernetes version, image, CVE) cell. Absence of a CVE from a scan is \u201Cnot observed,\u201D never a proof of safety.",
      PRESENTATION_LABELS, PRESENTATION_HELP,
      ps.counts, ps.shares, ps.total),

    glossarySection("Attribution — how an AKS-release image maps to Kubernetes",
      attr.total ? "Counts are measured from the current build." : null,
      ATTRIBUTION_LABELS, ATTRIBUTION_HELP, attr.counts, attr.shares, attr.total),

    glossarySection("First-fix provenance (AKS release axis)",
      ff.total ? "Counts are measured from the current build." : null,
      FIRST_FIXED_SOURCE_LABELS, FIRST_FIXED_SOURCE_HELP, ff.counts, ff.shares, ff.total),

    el("h3", null, "Data contract"),
    el("p", { class: "note" }, "The feed is plain JSON you can consume directly. Read the endpoints, don't scrape this HTML:"),
    el("dl", { class: "kv help-kv" }, [
      el("dt", null, "data/_index.json"), el("dd", null, "Entry point: scanned Kubernetes versions (report_time, scan_age_days, cohort, comparable_with), AKS releases, cohorts and chain_issues."),
      el("dt", null, "data/k8s/<version>.json"), el("dd", null, "One Kubernetes version; images[] pre-sorted by CVE count descending."),
      el("dt", null, "data/cve/<CVE>.json"), el("dd", null, "One CVE across both axes, kept separate: k8s[] (snapshots) and releases[] (release history, each with its attribution)."),
      el("dt", null, "data/release/<version>.json"), el("dd", null, "One AKS release; home of images that cannot be mapped to any Kubernetes version (k8s_unmapped). Carries first_fixes[]."),
      el("dt", null, "data/cve-index.json"), el("dd", null, "Slim triage: CVE → affected Kubernetes minors, interned."),
      el("dt", null, "data/image/index.json + <slug>.json"), el("dd", null, "Per-image detail. Resolve a repo to its file through the index — never guess the filename. Optional (may be absent in this build)."),
      el("dt", null, "data/glossary.json"), el("dd", null, "This controlled vocabulary, with per-value counts measured from the build."),
      el("dt", null, "data/manifest.json"), el("dd", null, "Generated inventory of every endpoint with real byte sizes and optional flags."),
    ]),
    el("p", { class: "note" }, ["Agent overview and the full recipe: ", el("a", { href: "llms.txt" }, "llms.txt"), "."]),
  ]);
  $app().replaceChildren(view);
  setGeneratedFooter();
}

/* ---------- footer + routing ---------- */

function setGeneratedFooter() {
  const gEl = document.getElementById("feed-generated");
  if (gEl && state.index && state.index.generated) {
    const c = state.index.counts || {};
    gEl.textContent = "Feed generated " + state.index.generated +
      " · " + (c.k8s_versions || (state.index.k8s_versions || []).length) + " Kubernetes versions, " +
      (c.aks_releases || (state.index.aks_releases || []).length) + " AKS releases.";
  }
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const qi = raw.indexOf("?");
  const pathRaw = qi >= 0 ? raw.slice(0, qi) : raw;
  const query = new URLSearchParams(qi >= 0 ? raw.slice(qi + 1) : "");
  const parts = pathRaw.split("/").filter((s) => s.length).map((s) => {
    try { return decodeURIComponent(s); } catch (_e) { return s; }
  });
  return { parts, query };
}

async function route() {
  if (!state.index) return;
  const { parts, query } = parseHash();
  const seg0 = parts[0] || "";
  try {
    if (!seg0) { renderHome(); return; }
    if (/^(help|glossary)$/i.test(seg0)) { renderHelp(); return; }
    if (/^image$/i.test(seg0)) { await renderImage(parts.slice(1).join("/")); return; }
    if (/^\d+\.\d+/.test(seg0)) {
      if (parts.length >= 2) { await renderCve(seg0, parts[1]); return; }
      await renderVersion(seg0, query);
      return;
    }
    renderHome({ unknown: seg0 });
  } catch (e) {
    $app().replaceChildren(el("div", { class: "error" }, "Something went wrong rendering this view (" + e.message + ")."));
  }
  window.scrollTo(0, 0);
}

async function main() {
  try {
    await loadIndex();
  } catch (e) {
    $app().replaceChildren(el("div", { class: "error" },
      "Failed to load the container-image feed (" + e.message + "). " +
      "The images feed is built by a separate job and may not be published yet; " +
      "if running locally, serve the repo root and open /site/images/ after building " +
      "a feed into ./feed-out/images, or pass ?data=<path>."));
    return;
  }
  // First paint must not wait on the optional glossary.json. Render immediately
  // from _index.json, then load glossary.json off the critical path and
  // re-render the current view only if a document actually arrived. A missing
  // (404) or hung glossary can therefore never delay or block first paint.
  setGeneratedFooter();
  window.addEventListener("hashchange", route);
  await route();
  // LOAD-BEARING ORDER: route() (first paint) must run and be awaited BEFORE
  // this line, and this loadGlossary() call must stay fire-and-forget (NOT
  // awaited). Awaiting the optional glossary here reintroduces a blocking-hang
  // (a stalled glossary.json would freeze first paint). Enforced by
  // tests/test_ccp_site_vocab.py::MainRenderOrderTest — do not "tidy" into an await.
  loadGlossary().then((doc) => { if (doc) route(); });
}

document.addEventListener("DOMContentLoaded", main);
