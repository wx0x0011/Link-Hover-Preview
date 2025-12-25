const keyEl = document.getElementById("key");
const malRedEl = document.getElementById("malRed");
const susYellowEl = document.getElementById("susYellow");

const statusEl = document.getElementById("status");
const saveBtn = document.getElementById("save");

const DEFAULTS = {
  maliciousRed: 2,
  suspiciousYellow: 2
};

function setStatus(text, ok = true) {
  statusEl.textContent = text;
  statusEl.style.color = ok ? "#0a7a2f" : "#b00020";
}

function clampInt(v, fallback) {
  const n = Number.parseInt(String(v), 10);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return n;
}

async function load() {
  const { vtApiKey, vtThresholds } = await chrome.storage.sync.get(["vtApiKey", "vtThresholds"]);
  keyEl.value = vtApiKey || "";

  const t = vtThresholds || {};
  malRedEl.value = clampInt(t.maliciousRed, DEFAULTS.maliciousRed);
  susYellowEl.value = clampInt(t.suspiciousYellow, DEFAULTS.suspiciousYellow);
}
load();

saveBtn.addEventListener("click", async () => {
  const vtApiKey = (keyEl.value || "").trim();

  const vtThresholds = {
    maliciousRed: clampInt(malRedEl.value, DEFAULTS.maliciousRed),
    suspiciousYellow: clampInt(susYellowEl.value, DEFAULTS.suspiciousYellow)
  };

  await chrome.storage.sync.set({ vtApiKey, vtThresholds });

  if (!vtApiKey) {
    setStatus("Saved. (API key is empty — VirusTotal checks will be disabled.)", false);
  } else {
    setStatus(`Saved. Red: malicious ≥ ${vtThresholds.maliciousRed}, Yellow: suspicious ≥ ${vtThresholds.suspiciousYellow}`, true);
  }
});
