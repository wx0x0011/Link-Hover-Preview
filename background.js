// background.js (MV3 service worker)

const VT_BASE = "https://www.virustotal.com/api/v3";
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_CACHE_SIZE = 500;
const STORAGE_PREF_KEY = "settingsStorageArea";

const cache = new Map(); // url -> { ts, result }
const inflight = new Map(); // url -> Promise

let storageAreaCache = { area: "sync", ts: 0 };

function pruneCache() {
  const now = Date.now();
  for (const [url, v] of cache) {
    if (now - v.ts > CACHE_TTL_MS) cache.delete(url);
  }

  while (cache.size > MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
}

function getStorageByArea(area) {
  return area === "local" ? chrome.storage.local : chrome.storage.sync;
}

async function getStorageAreaName() {
  const now = Date.now();
  if (now - storageAreaCache.ts < 5_000) {
    return storageAreaCache.area;
  }

  const { [STORAGE_PREF_KEY]: area } = await chrome.storage.local.get([STORAGE_PREF_KEY]);
  const normalized = area === "local" ? "local" : "sync";
  storageAreaCache = { area: normalized, ts: now };
  return normalized;
}

async function storageGet(keys) {
  const area = await getStorageAreaName();
  return getStorageByArea(area).get(keys);
}

async function getApiKey() {
  const { vtApiKey } = await storageGet(["vtApiKey"]);
  return (vtApiKey || "").trim();
}

async function getThresholds() {
  const { vtThresholds } = await storageGet(["vtThresholds"]);
  const t = vtThresholds || {};
  return {
    maliciousRed: Number.isFinite(Number(t.maliciousRed)) ? Math.max(0, parseInt(t.maliciousRed, 10)) : 2,
    suspiciousYellow: Number.isFinite(Number(t.suspiciousYellow)) ? Math.max(0, parseInt(t.suspiciousYellow, 10)) : 2
  };
}

function normalizeUrl(url) {
  return String(url || "").trim();
}

function isSupportedUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

async function vtFetch(path, { method = "GET", apiKey, body } = {}) {
  const headers = {
    "x-apikey": apiKey
  };

  if (body instanceof URLSearchParams) {
    headers["content-type"] = "application/x-www-form-urlencoded";
  }

  const resp = await fetch(`${VT_BASE}${path}`, { method, headers, body });
  const text = await resp.text();

  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // keep json as null
  }

  return { ok: resp.ok, status: resp.status, json, raw: text };
}

function computeRingScore(stats, thresholds) {
  const harmless = Number(stats?.harmless ?? 0);
  const undetected = Number(stats?.undetected ?? 0);
  const suspicious = Number(stats?.suspicious ?? 0);
  const malicious = Number(stats?.malicious ?? 0);
  const timeout = Number(stats?.timeout ?? 0);
  const total = harmless + undetected + suspicious + malicious + timeout;

  const score = harmless + undetected;

  const redTh = thresholds?.maliciousRed ?? 2;
  const yellowTh = thresholds?.suspiciousYellow ?? 2;

  let verdict = "unknown";
  if (malicious >= redTh && total > 0) verdict = "malicious";
  else if (suspicious >= yellowTh && total > 0) verdict = "suspicious";
  else if (total > 0) verdict = "clean";

  return {
    score,
    total: total || 0,
    verdict,
    thresholds: { maliciousRed: redTh, suspiciousYellow: yellowTh },
    stats: { harmless, undetected, suspicious, malicious, timeout }
  };
}

async function checkUrlWithVT(url) {
  pruneCache();
  url = normalizeUrl(url);

  if (!url) return { status: "bad_url" };
  if (!isSupportedUrl(url)) return { status: "unsupported_protocol" };

  const cached = cache.get(url);
  if (cached && Date.now() - cached.ts <= CACHE_TTL_MS) {
    return { status: "ok", ...cached.result, cached: true };
  }

  if (inflight.has(url)) return inflight.get(url);

  const p = (async () => {
    const apiKey = await getApiKey();
    if (!apiKey) return { status: "no_key" };

    const form = new URLSearchParams();
    form.set("url", url);

    const sub = await vtFetch("/urls", { method: "POST", apiKey, body: form });

    if (!sub.ok) {
      if (sub.status === 401 || sub.status === 403) return { status: "auth_error", code: sub.status };
      if (sub.status === 429) return { status: "rate_limited", code: 429 };
      return { status: "submit_error", code: sub.status, detail: sub.json || sub.raw };
    }

    const analysisId = sub.json?.data?.id;
    if (!analysisId) return { status: "submit_error", code: sub.status, detail: sub.json || sub.raw };

    // POST /urls returns analysis id, so follow up with /analyses/{id}.
    const analysis = await vtFetch(`/analyses/${encodeURIComponent(analysisId)}`, { method: "GET", apiKey });

    if (!analysis.ok) {
      if (analysis.status === 401 || analysis.status === 403) return { status: "auth_error", code: analysis.status };
      if (analysis.status === 429) return { status: "rate_limited", code: 429 };
      return { status: "analysis_error", code: analysis.status, detail: analysis.json || analysis.raw };
    }

    const attrs = analysis.json?.data?.attributes;
    const stats = attrs?.stats || attrs?.last_analysis_stats;
    const analysisDate = attrs?.date ?? attrs?.last_analysis_date ?? null;
    const thresholds = await getThresholds();
    const ring = computeRingScore(stats, thresholds);

    const result = {
      ring,
      analysisDate: analysisDate ?? null
    };

    cache.set(url, { ts: Date.now(), result });
    pruneCache();

    return { status: "ok", ...result, cached: false };
  })().finally(() => inflight.delete(url));

  inflight.set(url, p);
  return p;
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (!Object.prototype.hasOwnProperty.call(changes, STORAGE_PREF_KEY)) return;
  storageAreaCache.ts = 0;
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "vt_check") {
    checkUrlWithVT(msg.url)
      .then(sendResponse)
      .catch((e) => sendResponse({ status: "exception", detail: String(e?.message || e) }));
    return true;
  }
});
