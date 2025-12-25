let tip = null;
let lastAnchor = null;
let hoverTimer = null;

let lastMouseX = 0;
let lastMouseY = 0;
let rafPending = false;

function ensureTip() {
  if (tip) return tip;

  tip = document.createElement("div");
  tip.style.position = "fixed";
  tip.style.zIndex = "999999";
  tip.style.maxWidth = "560px";
  tip.style.padding = "10px 12px";
  tip.style.borderRadius = "12px";
  tip.style.background = "rgba(20,20,20,0.92)";
  tip.style.color = "#fff";
  tip.style.fontSize = "12px";
  tip.style.lineHeight = "1.35";
  tip.style.boxShadow = "0 10px 30px rgba(0,0,0,0.25)";
  tip.style.pointerEvents = "none";
  tip.style.display = "none";

  // Layout: left content (url) + right ring
  tip.innerHTML = `
    <div style="display:flex; align-items:center; gap:10px;">
      <div id="lhp_url" style="flex:1; word-break:break-all;"></div>
      <div id="lhp_ring" style="width:44px; height:44px; flex:0 0 auto;"></div>
    </div>
    <div id="lhp_sub" style="margin-top:6px; color: rgba(255,255,255,0.75); font-size:11px;"></div>
  `;

  document.documentElement.appendChild(tip);
  return tip;
}

function setTipPosition(x, y) {
  const t = ensureTip();
  const w = 580, h = 150;
  t.style.left = Math.min(x + 12, window.innerWidth - w) + "px";
  t.style.top = Math.min(y + 12, window.innerHeight - h) + "px";
}

function showTip(url) {
  const t = ensureTip();
  t.querySelector("#lhp_url").textContent = url;
  t.querySelector("#lhp_sub").textContent = "";
  setRingState({ mode: "idle" });
  t.style.display = "block";
  // position immediately
  setTipPosition(lastMouseX, lastMouseY);
}

function hideTip() {
  if (tip) tip.style.display = "none";
  lastAnchor = null;
  if (hoverTimer) {
    clearTimeout(hoverTimer);
    hoverTimer = null;
  }
}

function getAnchor(el) {
  return el?.closest?.("a[href]") || null;
}

// Ring UI
function ringColor(verdict) {
  if (verdict === "malicious") return "#ff4d4f";   // red
  if (verdict === "suspicious") return "#faad14";  // yellow
  if (verdict === "clean") return "#52c41a";       // green
  return "#999";                                  // gray
}

function setRingState(state) {
  const t = ensureTip();
  const ring = t.querySelector("#lhp_ring");

  // Modes:
  // idle (no key / not checked), loading, ok, error
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

    // circle circumference for r=15.5 is about 97.39
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

  // idle
  ring.innerHTML = `
    <svg width="44" height="44" viewBox="0 0 36 36">
      <circle cx="18" cy="18" r="15.5" stroke="rgba(255,255,255,0.15)" stroke-width="3" fill="none"></circle>
      <text x="18" y="21" text-anchor="middle" font-size="9" fill="#fff">--</text>
    </svg>
  `;
}

function setSub(text) {
  const t = ensureTip();
  t.querySelector("#lhp_sub").textContent = text || "";
}

// Throttled position update
function scheduleRafPosition() {
  if (rafPending) return;
  rafPending = true;
  requestAnimationFrame(() => {
    rafPending = false;
    if (!tip || tip.style.display === "none") return;
    setTipPosition(lastMouseX, lastMouseY);
  });
}

// VT query (hover only)
async function queryVT(url) {
  setRingState({ mode: "loading" });
  setSub("Checking VirusTotal…");

  let resp = null;
  try {
    resp = await chrome.runtime.sendMessage({ type: "vt_check", url });
  } catch (e) {
    setRingState({ mode: "error" });
    setSub("VT check failed (runtime).");
    return;
  }

  // If user has moved away
  if (!lastAnchor || lastAnchor.href !== url) return;

  if (!resp || !resp.status) {
    setRingState({ mode: "error" });
    setSub("VT check failed (no response).");
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

  // other errors
  setRingState({ mode: "error" });
  const code = resp.code ? ` (${resp.code})` : "";
  setSub(`VT error${code}: ${resp.status}`);
}

// Pointer events: only trigger on anchor change
document.addEventListener("pointerover", (e) => {
  const a = getAnchor(e.target);
  if (!a) return;

  // Ignore same anchor
  if (a === lastAnchor) return;

  lastAnchor = a;
  showTip(a.href);

  // Debounce VT query
  if (hoverTimer) clearTimeout(hoverTimer);
  hoverTimer = setTimeout(() => {
    // ensure still same anchor
    if (lastAnchor && lastAnchor.href === a.href) {
      queryVT(a.href);
    }
  }, 220);
}, { passive: true });

document.addEventListener("pointerout", (e) => {
  // If leaving the anchor entirely
  const fromA = getAnchor(e.target);
  const toA = getAnchor(e.relatedTarget);

  if (fromA && fromA === lastAnchor && toA !== fromA) {
    hideTip();
  }
}, { passive: true });

document.addEventListener("pointermove", (e) => {
  lastMouseX = e.clientX;
  lastMouseY = e.clientY;
  if (tip && tip.style.display !== "none") {
    scheduleRafPosition();
  }
}, { passive: true });

document.addEventListener("scroll", hideTip, { passive: true });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideTip();
}, { passive: true });
