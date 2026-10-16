const STORAGE_PREF_KEY = "settingsStorageArea";
const HOVER_DELAY_MS = 220;
let brandGuardEnabled = true;
const brandGuardWarnings = new WeakMap();

chrome.storage.local.get(["lhpBrandGuardEnabled"]).then(({lhpBrandGuardEnabled}) => {
  brandGuardEnabled = lhpBrandGuardEnabled !== false;
}).catch(() => {});

function inspectBrandGuard(anchor) {
  if (!brandGuardEnabled || !globalThis.LHPBrandGuard) return { status: "none" };
  const verdict = globalThis.LHPBrandGuard.analyze(anchor.href, anchor.textContent || "");
  brandGuardWarnings.set(anchor, { href: anchor.href, verdict });
  return verdict;
}
function brandGuardMessage(result) {
  if (result.status === "warning") {
    return "⚠ Possible " + result.brand + " impersonation: expected " +
      result.expectedDomain + ", actual " + result.hostname + ". " + result.reason;
  }
  if (result.status === "notice") return "ℹ Domain caution: " + result.reason;
  return "";
}

let tipHost = null;
let tipShadow = null;
let tipEls = null;
let lastAnchor = null;
let hoverTimer = null;

let lastMouseX = 0;
let lastMouseY = 0;
let rafPending = false;
let queryToken = 0;

function clamp(n, min, max) {
  return Math.min(Math.max(n, min), max);
}

function isSupportedProtocol(href) {
  try {
    const url = new URL(href);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function ensureTip() {
  if (tipHost) return tipHost;

  tipHost = document.createElement("div");
  tipHost.id = "lhp-tooltip-host";
  tipHost.style.position = "fixed";
  tipHost.style.left = "0";
  tipHost.style.top = "0";
  tipHost.style.zIndex = "2147483647";
  tipHost.style.pointerEvents = "none";
  tipHost.style.display = "none";

  tipShadow = tipHost.attachShadow({ mode: "open" });
  tipShadow.innerHTML = `
    <style>
      :host {
        all: initial;
      }
      .lhp-tip {
        max-width: 560px;
        padding: 10px 12px;
        border-radius: 12px;
        background: rgba(20, 20, 20, 0.92);
        color: #fff;
        font-size: 12px;
        line-height: 1.35;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
        border: 1px solid rgba(255, 255, 255, 0.1);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      .lhp-main {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .lhp-url {
        flex: 1;
        min-width: 0;
        word-break: break-all;
      }
      .lhp-ring {
        width: 44px;
        height: 44px;
        flex: 0 0 auto;
      }
      .lhp-sub {
        margin-top: 6px;
        color: rgba(255, 255, 255, 0.75);
        font-size: 11px;
      }
    </style>
    <div class="lhp-tip" role="tooltip" aria-live="polite">
      <div class="lhp-main">
        <div id="lhp_url" class="lhp-url"></div>
        <div id="lhp_ring" class="lhp-ring"></div>
      </div>
      <div id="lhp_sub" class="lhp-sub"></div>
    </div>
  `;

  tipEls = {
    url: tipShadow.getElementById("lhp_url"),
    ring: tipShadow.getElementById("lhp_ring"),
    sub: tipShadow.getElementById("lhp_sub"),
    brand: tipShadow.getElementById("lhp_brand")
  };

  document.documentElement.appendChild(tipHost);
  return tipHost;
}

function setTipPosition(x, y) {
  const t = ensureTip();
  const margin = 8;
  const offset = 12;

  const rect = t.getBoundingClientRect();
  const maxLeft = Math.max(0, window.innerWidth - rect.width - margin);
  const maxTop = Math.max(0, window.innerHeight - rect.height - margin);

  const left = clamp(x + offset, 0, maxLeft);
  const top = clamp(y + offset, 0, maxTop);

  t.style.left = `${left}px`;
  t.style.top = `${top}px`;
}

function showTip(url) {
  const t = ensureTip();
  tipEls.url.textContent = url;
  tipEls.sub.textContent = "";
  tipEls.brand.textContent = "";
  tipEls.brand.style.display = "none";
  setRingState({ mode: "idle" });
  t.style.display = "block";
  setTipPosition(lastMouseX, lastMouseY);
}

function hideTip() {
  if (tipHost) tipHost.style.display = "none";
  lastAnchor = null;
  queryToken += 1;
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
}

function getAnchor(el) {
  return el?.closest?.("a[href]") || null;
}

function ringColor(verdict) {
  if (verdict === "malicious") return "#ff4d4f";
  if (verdict === "suspicious") return "#faad14";
  if (verdict === "clean") return "#52c41a";
  return "#999";
}

function setRingState(state) {
  ensureTip();
  const ring = tipEls.ring;

  if (state.mode === "loading") {
    ring.innerHTML = `
      <svg width="44" height="44" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r="15.5" stroke="rgba(255,255,255,0.15)" stroke-width="3" fill="none"></circle>
        <circle cx="18" cy="18" r="15.5" stroke="#5dade2" stroke-width="3" fill="none"
          stroke-dasharray="24 74" stroke-linecap="round"
          transform="rotate(-90 18 18)">
          <animateTransform attributeName="transform" type="rotate"
            from="0 18 18" to="360 18 18" dur="1s" repeatCount="indefinite"/>
        </circle>
        <text x="18" y="21" text-anchor="middle" font-size="9" fill="#fff">VT</text>
      </svg>
    `;
    return;
  }

  if (state.mode === "error") {
    ring.innerHTML = `
      <svg width="44" height="44" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r="15.5" stroke="rgba(255,255,255,0.15)" stroke-width="3" fill="none"></circle>
        <circle cx="18" cy="18" r="15.5" stroke="#ff4d4f" stroke-width="3" fill="none"
          stroke-dasharray="97" stroke-dashoffset="0"
          stroke-linecap="round" transform="rotate(-90 18 18)"></circle>
        <text x="18" y="21" text-anchor="middle" font-size="11" fill="#fff">!</text>
      </svg>
    `;
    return;
  }

  if (state.mode === "ok") {
    const score = state.score ?? 0;
    const total = state.total ?? 0;

    const safeTotal = total > 0 ? total : 1;
    const ratio = Math.max(0, Math.min(1, score / safeTotal));

    const C = 97.39;
    const dash = C * ratio;
    const gap = C - dash;

    const color = ringColor(state.verdict);
    ring.innerHTML = `
      <svg width="44" height="44" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r="15.5" stroke="rgba(255,255,255,0.15)" stroke-width="3" fill="none"></circle>
        <circle cx="18" cy="18" r="15.5" stroke="${color}" stroke-width="3" fill="none"
          stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}"
          stroke-linecap="round" transform="rotate(-90 18 18)"></circle>
        <text x="18" y="21" text-anchor="middle" font-size="9" fill="#fff">${score}</text>
      </svg>
    `;
    return;
  }

  ring.innerHTML = `
    <svg width="44" height="44" viewBox="0 0 36 36">
      <circle cx="18" cy="18" r="15.5" stroke="rgba(255,255,255,0.15)" stroke-width="3" fill="none"></circle>
      <text x="18" y="21" text-anchor="middle" font-size="9" fill="#fff">--</text>
    </svg>
  `;
}

function setSub(text) {
  ensureTip();
  tipEls.sub.textContent = text || "";
  if (tipHost && tipHost.style.display !== "none") {
    setTipPosition(lastMouseX, lastMouseY);
  }
}

function scheduleRafPosition() {
  if (rafPending) return;
  rafPending = true;
  requestAnimationFrame(() => {
    rafPending = false;
    if (!tipHost || tipHost.style.display === "none") return;
    setTipPosition(lastMouseX, lastMouseY);
  });
}

async function queryVT(url) {
  const token = ++queryToken;
  setRingState({ mode: "loading" });
  setSub("Checking VirusTotal…");

  let resp = null;
  try {
    resp = await chrome.runtime.sendMessage({ type: "vt_check", url });
  } catch {
    if (token !== queryToken) return;
    setRingState({ mode: "error" });
    setSub("VT check failed (runtime).");
    return;
  }

  if (token !== queryToken) return;
  if (!lastAnchor || lastAnchor.href !== url) return;

  if (!resp || !resp.status) {
    setRingState({ mode: "error" });
    setSub("VT check failed (no response).");
    return;
  }

  if (resp.status === "unsupported_protocol") {
    setRingState({ mode: "idle" });
    setSub("Protocol is not supported by VT check.");
    return;
  }

  if (resp.status === "no_key") {
    setRingState({ mode: "idle" });
    setSub("No VirusTotal API key. Set it in extension options.");
    return;
  }

  if (resp.status === "ok") {
    const ring = resp.ring;
    setRingState({
      mode: "ok",
      score: ring.score,
      total: ring.total,
      verdict: ring.verdict
    });

    const s = ring.stats;
    const cached = resp.cached ? " (cached)" : "";
    setSub(`VT: harmless ${s.harmless}, undetected ${s.undetected}, suspicious ${s.suspicious}, malicious ${s.malicious}${cached}`);
    return;
  }

  setRingState({ mode: "error" });
  const code = resp.code ? ` (${resp.code})` : "";
  setSub(`VT error${code}: ${resp.status}`);
}

document.addEventListener("pointerover", (e) => {
  const a = getAnchor(e.target);
  if (!a) return;

  if (a === lastAnchor) return;

  const href = a.href;
  if (!href) return;

  lastAnchor = a;
  showTip(href);
  const brandResult = inspectBrandGuard(a);
  const brandText = brandGuardMessage(brandResult);
  if (brandText) {
    tipEls.brand.textContent = brandText;
    tipEls.brand.style.display = "block";
    setTipPosition(lastMouseX, lastMouseY);
  }

  if (!isSupportedProtocol(href)) {
    setRingState({ mode: "idle" });
    setSub("Unsupported protocol. VT check skipped.");
    return;
  }

  if (hoverTimer) clearTimeout(hoverTimer);
  hoverTimer = setTimeout(() => {
    if (lastAnchor && lastAnchor.href === href) {
      queryVT(href);
    }
  }, HOVER_DELAY_MS);
}, { passive: true });

document.addEventListener("pointerout", (e) => {
  const fromA = getAnchor(e.target);
  const toA = getAnchor(e.relatedTarget);

  if (fromA && fromA === lastAnchor && toA !== fromA) {
    hideTip();
  }
}, { passive: true });

document.addEventListener("pointermove", (e) => {
  lastMouseX = e.clientX;
  lastMouseY = e.clientY;
  if (tipHost && tipHost.style.display !== "none") {
    scheduleRafPosition();
  }
}, { passive: true });

document.addEventListener("scroll", hideTip, { passive: true });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) hideTip();
}, { passive: true });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideTip();
}, { passive: true });

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (!Object.prototype.hasOwnProperty.call(changes, STORAGE_PREF_KEY)) return;

  if (tipHost && tipHost.style.display !== "none" && lastAnchor?.href) {
    const href = lastAnchor.href;
    if (isSupportedProtocol(href)) {
      queryVT(href);
    }
  }
});

/* High-confidence domain lookalikes require an explicit second click.
 * Never silently navigate or alter the link. Only active for warnings. */
let approvedNavigation = null;
document.addEventListener("click", (e) => {
  const anchor = getAnchor(e.target);
  if (!anchor || !brandGuardEnabled || !globalThis.LHPBrandGuard) return;
  const url = anchor.href;
  if (approvedNavigation === url) {
    approvedNavigation = null;
    return;
  }
  const verdict = inspectBrandGuard(anchor);
  if (verdict.status !== "warning") return;
  e.preventDefault();
  e.stopImmediatePropagation();
  const confirmed = window.confirm(
    "Link Hover Preview — BrandGuard\n\n" +
    "Possible " + verdict.brand + " impersonation.\n" +
    "Expected official domain: " + verdict.expectedDomain + "\n" +
    "Actual destination: " + verdict.hostname + "\n\n" +
    verdict.reason + "\n\n" +
    "This is a heuristic warning, not a malware verdict.\n\n" +
    "Continue to this link anyway?"
  );
  if (!confirmed) return;
  approvedNavigation = url;
  // Use a browser-native anchor navigation rather than extension-side fetch.
  anchor.click();
}, true);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.lhpBrandGuardEnabled) {
    brandGuardEnabled = changes.lhpBrandGuardEnabled.newValue !== false;
  }
});
