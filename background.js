// background.js (MV3 service worker)

const VT_BASE = "https://www.virustotal.com/api/v3";
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_CACHE_SIZE = 500;

const cache = new Map(); // url -> { ts, result }
const inflight = new Map(); // url -> Promise

function pruneCache() {
  // remove expired
  const now = Date.now();
  for (const [url, v] of cache) {
    if (now - v.ts > CACHE_TTL_MS) cache.delete(url);
  }
  // cap size (naive FIFO by insertion order)
  while (cache.size > MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
}

async function getApiKey() {
  const { vtApiKey } = await chrome.storage.sync.get(["vtApiKey"]);
  return (vtApiKey || "").trim();
}

async function vtFetch(path, { method = "GET", apiKey, body } = {}) {
  const headers = {
    "x-apikey": apiKey
  };

  // VT URL submission expects form-encoded body
  if (body instanceof URLSearchParams) {
    headers["content-type"] = "application/x-www-form-urlencoded";
  }

  const resp = await fetch(`${VT_BASE}${path}`, { method, headers, body });
  const text = await resp.text();

  let json = null;
  try { json = JSON.parse(text); } catch { /* ignore */ }

  return { ok: resp.ok, status: resp.status, json, raw: text };
}

function normalizeUrl(url) {
  // Keep as-is, but strip trailing spaces
  return String(url || "").trim();
}

function computeRingScore(stats) {
  // stats: { harmless, malicious, suspicious, undetected, timeout, ... }
  const harmless = Number(stats?.harmless ?? 0);
  const undetected = Number(stats?.undetected ?? 0);
  const suspicious = Number(stats?.suspicious ?? 0);
  const malicious = Number(stats?.malicious ?? 0);
  const timeout = Number(stats?.timeout ?? 0);
  const total = harmless + undetected + suspicious + malicious + timeout;

  // “score” 这里按“非恶意/非可疑”为主的正向分：
  const score = harmless + undetected;

  let verdict = "unknown";
  if (malicious > 0) verdict = "malicious";
  else if (suspicious > 0) verdict = "suspicious";
  else if (total > 0) verdict = "clean";

  return { score, total: total || 0, verdict, stats: { harmless, undetected, suspicious, malicious, timeout } };
}

async function checkUrlWithVT(url) {
  pruneCache();
  url = normalizeUrl(url);
  if (!url) return { status: "bad_url" };

  const cached = cache.get(url);
  if (cached && Date.now() - cached.ts <= CACHE_TTL_MS) {
    return { status: "ok", ...cached.result, cached: true };
  }

  if (inflight.has(url)) return inflight.get(url);

  const p = (async () => {
    const apiKey = await getApiKey();
    if (!apiKey) return { status: "no_key" };

    // 1) Submit URL to get its ID (VT will return an id we can use for GET)
    const form = new URLSearchParams();
    form.set("url", url);

    const sub = await vtFetch("/urls", { method: "POST", apiKey, body: form });

    // Common cases:
    // - 200/201 OK: return data.id
    // - 429 rate limited
    // - 401 invalid key
    if (!sub.ok) {
      if (sub.status === 401 || sub.status === 403) return { status: "auth_error", code: sub.status };
      if (sub.status === 429) return { status: "rate_limited", code: 429 };
      return { status: "submit_error", code: sub.status, detail: sub.json || sub.raw };
    }

    const id = sub.json?.data?.id;
    if (!id) return { status: "submit_error", code: sub.status, detail: sub.json || sub.raw };

    // 2) Fetch report by id
    const rep = await vtFetch(`/urls/${encodeURIComponent(id)}`, { method: "GET", apiKey });

    if (!rep.ok) {
      if (rep.status === 401 || rep.status === 403) return { status: "auth_error", code: rep.status };
      if (rep.status === 429) return { status: "rate_limited", code: 429 };
      return { status: "report_error", code: rep.status, detail: rep.json || rep.raw };
    }

    const attrs = rep.json?.data?.attributes;
    const stats = attrs?.last_analysis_stats;
    const analysisDate = attrs?.last_analysis_date; // unix seconds (often)
    const ring = computeRingScore(stats);

    const result = {
      ring,
      analysisDate: analysisDate ?? null
    };

    cache.set(url, { ts: Date.now(), result });
    pruneCache();

    return { status: "ok", ...result, cached: false };
  })()
    .finally(() => inflight.delete(url));

  inflight.set(url, p);
  return p;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "vt_check") {
    checkUrlWithVT(msg.url)
      .then(sendResponse)
      .catch((e) => sendResponse({ status: "exception", detail: String(e?.message || e) }));
    return true; // keep channel open
  }
});
