# Link Hover Preview

A lightweight browser extension that shows link URLs on hover, with optional **VirusTotal safety indicators** displayed as a circular score.

## Features

- Instant link preview on hover
- Optional VirusTotal URL checks (API key required)
- Ring risk indicator
- Customizable malicious/suspicious thresholds
- Storage mode selector
  - `Sync`: use browser profile sync storage
  - `Local`: keep data on current device only
- API key field uses password mode with show/hide toggle
- Protocol guard in content script (only `http/https` is checked by VT)
- Tooltip rendered in Shadow DOM for better style isolation
- Performance optimizations
  - debounced hover checks
  - runtime and background-side request dedupe
  - background response cache
  - position updates via `requestAnimationFrame`

## Installation (Load Unpacked)

1. Download this repository.
2. Open browser extensions page:
   - Edge: `edge://extensions`
   - Chrome: `chrome://extensions`
3. Enable Developer mode.
4. Click **Load unpacked**.
5. Select this folder (contains `manifest.json`).

## Configuration

1. Open extension details.
2. Open **Extension options**.
3. Choose storage mode (`Sync` or `Local`).
4. Paste VirusTotal API key (optional).
5. Adjust thresholds if needed.
6. Click **Save**.

Without API key, URL preview still works and VT checks are skipped.

## VirusTotal API key

1. Visit <https://www.virustotal.com/>.
2. Sign in.
3. Open profile and copy your API key.

Free API plans are rate-limited.

## Notes

- VT verdict colors:
  - Green: clean
  - Yellow: suspicious (threshold reached)
  - Red: malicious (threshold reached)
- Threshold defaults:
  - malicious >= 2
  - suspicious >= 2
