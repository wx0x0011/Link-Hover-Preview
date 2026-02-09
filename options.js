const keyEl = document.getElementById("key");
const toggleKeyBtn = document.getElementById("toggleKey");
const malRedEl = document.getElementById("malRed");
const susYellowEl = document.getElementById("susYellow");
const storageSyncEl = document.getElementById("storageSync");
const storageLocalEl = document.getElementById("storageLocal");

const statusEl = document.getElementById("status");
const saveBtn = document.getElementById("save");

const STORAGE_PREF_KEY = "settingsStorageArea";

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

function getAreaFromUI() {
  return storageLocalEl.checked ? "local" : "sync";
}

function getStorageByArea(area) {
  return area === "local" ? chrome.storage.local : chrome.storage.sync;
}

async function getPreferredArea() {
  const { [STORAGE_PREF_KEY]: area } = await chrome.storage.local.get([STORAGE_PREF_KEY]);
  return area === "local" ? "local" : "sync";
}

async function readSettings(area) {
  const store = getStorageByArea(area);
  const { vtApiKey, vtThresholds } = await store.get(["vtApiKey", "vtThresholds"]);
  const t = vtThresholds || {};

  return {
    vtApiKey: vtApiKey || "",
    vtThresholds: {
      maliciousRed: clampInt(t.maliciousRed, DEFAULTS.maliciousRed),
      suspiciousYellow: clampInt(t.suspiciousYellow, DEFAULTS.suspiciousYellow)
    }
  };
}

function renderSettings(settings) {
  keyEl.value = settings.vtApiKey;
  malRedEl.value = settings.vtThresholds.maliciousRed;
  susYellowEl.value = settings.vtThresholds.suspiciousYellow;
}

async function load() {
  const area = await getPreferredArea();
  storageSyncEl.checked = area === "sync";
  storageLocalEl.checked = area === "local";

  const settings = await readSettings(area);
  renderSettings(settings);

  setStatus(`Loaded settings from ${area === "sync" ? "sync storage" : "local storage"}.`, true);
}

async function onAreaChanged() {
  const area = getAreaFromUI();
  await chrome.storage.local.set({ [STORAGE_PREF_KEY]: area });

  const settings = await readSettings(area);
  renderSettings(settings);

  setStatus(`Switched to ${area === "sync" ? "sync" : "local"} storage.`, true);
}

load();

storageSyncEl.addEventListener("change", onAreaChanged);
storageLocalEl.addEventListener("change", onAreaChanged);

toggleKeyBtn.addEventListener("click", () => {
  const isHidden = keyEl.type === "password";
  keyEl.type = isHidden ? "text" : "password";
  toggleKeyBtn.textContent = isHidden ? "Hide" : "Show";
});

saveBtn.addEventListener("click", async () => {
  const area = getAreaFromUI();
  await chrome.storage.local.set({ [STORAGE_PREF_KEY]: area });

  const vtApiKey = (keyEl.value || "").trim();

  const vtThresholds = {
    maliciousRed: clampInt(malRedEl.value, DEFAULTS.maliciousRed),
    suspiciousYellow: clampInt(susYellowEl.value, DEFAULTS.suspiciousYellow)
  };

  await getStorageByArea(area).set({ vtApiKey, vtThresholds });

  if (!vtApiKey) {
    setStatus(`Saved to ${area}. (API key is empty - VirusTotal checks will be disabled.)`, false);
  } else {
    setStatus(`Saved to ${area}. Red: malicious >= ${vtThresholds.maliciousRed}, Yellow: suspicious >= ${vtThresholds.suspiciousYellow}`, true);
  }
});
