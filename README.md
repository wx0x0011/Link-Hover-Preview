# Link Hover Preview

A lightweight browser extension that shows link URLs on hover, with optional **VirusTotal safety indicators** displayed as a circular score.

---

## ✨ Features

- 🔗 **Instant link preview**  
  Show the full URL when hovering over any link.

- 🛡 **VirusTotal integration (optional)**  
  Check link safety using VirusTotal URL analysis.

- 🎨 **Visual risk indicator (ring score)**  
  - 🟢 Green: clean  
  - 🟡 Yellow: suspicious  
  - 🔴 Red: malicious  

- ⚙️ **Customizable risk thresholds**  
  Adjust how strict the warning levels are to reduce false positives.

- ⚡ **Performance-friendly design**  
  - Triggered only on hover  
  - Debounced requests  
  - Background caching to minimize API usage  

- 🔒 **Privacy-first**  
  - No tracking  
  - No analytics  
  - API key never exposed to web pages  

---

## 📦 Installation

### Load unpacked (Developer mode)

1. Clone or download this repository
2. Open the browser extensions page  
   - Edge: `edge://extensions`  
   - Chrome: `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked**
5. Select the project root folder (contains `manifest.json`)

---

## ⚙️ Configuration

### VirusTotal API Key (optional)

VirusTotal integration is **optional**.

- Without an API key:
  - Link URLs will still be shown
  - No safety analysis will be performed

#### How to add your API key

1. Open the browser extensions page
2. Find **Link Hover Preview**
3. Click **Details**
4. Click **Extension options**
5. Paste your **VirusTotal API Key**
6. Click **Save**

No browser restart required.

---

### 🔑 How to get a VirusTotal API Key

1. Visit https://www.virustotal.com/
2. Sign in or create an account
3. Open your profile → **API key**
4. Copy your **Public API Key**

> ℹ️ Free API keys have rate limits.  
> This extension uses debounce and caching to reduce unnecessary requests.

---

## ⚠️ Risk Threshold Settings (False Positive Control)

VirusTotal aggregates results from many security engines.  
Occasional **false positives** may occur, especially from individual vendors.

This extension allows you to **customize risk thresholds** to better match your tolerance level.

### Default thresholds

- 🔴 **Red (Malicious)**: `malicious ≥ 2`
- 🟡 **Yellow (Suspicious)**: `suspicious ≥ 2`

### Verdict rules

- **Red** if malicious detections ≥ red threshold
- **Yellow** if red is not met and suspicious detections ≥ yellow threshold
- **Green** otherwise

### Tips

- Lower thresholds → stricter warnings, more alerts
- Higher thresholds → fewer false positives, less noise
- Setting thresholds to `0` makes the extension extremely strict

Thresholds can be adjusted in **Extension options** at any time.

---

## 🧠 How the ring score works

The circular score represents the number of engines that did **not** flag the link:

