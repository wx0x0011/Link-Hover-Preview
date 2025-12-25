const keyEl = document.getElementById("key");
const statusEl = document.getElementById("status");
const saveBtn = document.getElementById("save");

function setStatus(text, ok = true) {
  statusEl.textContent = text;
  statusEl.style.color = ok ? "#0a7a2f" : "#b00020";
}

async function load() {
  const { vtApiKey } = await chrome.storage.sync.get(["vtApiKey"]);
  keyEl.value = vtApiKey || "";
}
load();

saveBtn.addEventListener("click", async () => {
  const vtApiKey = (keyEl.value || "").trim();
  await chrome.storage.sync.set({ vtApiKey });
  setStatus(vtApiKey ? "Saved." : "Saved (empty key). VirusTotal checks will be disabled.", !!vtApiKey);
});
