let tip = null;
let lastAnchor = null;

function ensureTip() {
  if (tip) return tip;
  tip = document.createElement("div");
  tip.style.position = "fixed";
  tip.style.zIndex = "999999";
  tip.style.maxWidth = "520px";
  tip.style.padding = "10px 12px";
  tip.style.borderRadius = "10px";
  tip.style.background = "rgba(20,20,20,0.92)";
  tip.style.color = "#fff";
  tip.style.fontSize = "12px";
  tip.style.lineHeight = "1.35";
  tip.style.boxShadow = "0 10px 30px rgba(0,0,0,0.25)";
  tip.style.pointerEvents = "none";
  tip.style.display = "none";
  document.documentElement.appendChild(tip);
  return tip;
}

function showTip(x, y, url) {
  const t = ensureTip();
  t.textContent = url;
  const w = 540, h = 120;
  t.style.left = Math.min(x + 12, window.innerWidth - w) + "px";
  t.style.top  = Math.min(y + 12, window.innerHeight - h) + "px";
  t.style.display = "block";
}

function hideTip() {
  if (tip) tip.style.display = "none";
}

function getAnchor(el) {
  return el?.closest?.("a[href]") || null;
}

document.addEventListener("mousemove", (e) => {
  const a = getAnchor(e.target);
  if (!a) {
    lastAnchor = null;
    hideTip();
    return;
  }
  if (a !== lastAnchor) lastAnchor = a;
  showTip(e.clientX, e.clientY, a.href);
}, { passive: true });

document.addEventListener("scroll", hideTip, { passive: true });
