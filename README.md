# SPECTRE

**Stealthy Domain Reconnaissance Tool for Security Researchers**

Chrome Extension paired with a high-performance Python FastAPI backend for instant domain intelligence.

![Spectre Logo](extension/icons/icon128.png)

---

## 📁 Project Structure

```
Spectre/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── scanner.py           # Reconnaissance modules
│   └── requirements.txt     # Python dependencies
│
├── extension/
│   ├── manifest.json        # Chrome Extension manifest (V3)
│   ├── popup.html           # Extension popup UI
│   ├── styles.css           # Cyberpunk theme styles
│   ├── popup.js             # Frontend logic
│   └── icons/               # Extension icons
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
└── README.md
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **WHOIS Intel** | Registrar, creation/expiry dates, nameservers, organization. Warns if < 30 days until expiry |
| **IP & Hosting** | IP resolution, geolocation, ISP, ASN. Detects WAF/CDN (Cloudflare, Akamai, etc.) |
| **SSL Certificate** | Issuer, validity dates, protocol version, days remaining |
| **Subdomain Discovery** | Passive OSINT via Certificate Transparency logs (crt.sh) |
| **Tech Stack Detection** | Server/powered-by headers with CVE vulnerability mapping |
| **Historical Data** | Mock "Pro Feature" showing previous registrars and drop history |

---

## 🚀 Setup Guide

### Prerequisites

- **Python 3.8+**
- **Google Chrome** (or Chromium-based browser)
- **pip** (Python package manager)

### Step 1: Install Backend Dependencies

```powershell
cd Spectre\backend
pip install -r requirements.txt
```

### Step 2: Start the Backend Server

```powershell
cd Spectre\backend
python -m uvicorn main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
```

> **Keep this terminal open!** The backend must be running for the extension to work.

### Step 3: Create Extension Icons

Before loading the extension, create placeholder icons or use the provided ones:

1. Create the `icons` folder: `extension/icons/`
2. Add 16x16, 48x48, and 128x128 PNG icons named `icon16.png`, `icon48.png`, `icon128.png`

> Or copy any square PNG and rename them accordingly.

### Step 4: Load Chrome Extension

1. Open Chrome and navigate to: `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **"Load unpacked"**
4. Select the `extension` folder: `Spectre\extension`
5. The Spectre icon (👻) should appear in your toolbar

### Step 5: Use Spectre

1. Navigate to any website (e.g., `https://google.com`)
2. Click the **Spectre** extension icon
3. Watch the radar animation as it scans
4. Explore the intelligence results!

---

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/scan?domain=example.com` | GET | Full domain reconnaissance |
| `/health` | GET | Detailed service status |

### Example API Call

```powershell
curl "http://localhost:8000/scan?domain=google.com"
```

---

## 🎨 UI Theme

The extension features a **Cyberpunk/Ghost** aesthetic:

- **Background**: `#0a0a0a` (Deep black)
- **Primary Accent**: `#bf00ff` (Neon purple)
- **Secondary Accent**: `#00f0ff` (Cyan)
- **Text**: Ghost white (`#f0f0f0`)
- **Radar scanning animation**
- **Glassmorphism effects**
- **Smooth micro-animations**

---

## ⚠️ Troubleshooting

### "Cannot connect to Spectre backend"
- Ensure the FastAPI server is running on `http://localhost:8000`
- Check the terminal for errors
- Try: `curl http://localhost:8000/`

### "Cannot scan browser internal pages"
- Spectre cannot scan `chrome://` or `chrome-extension://` URLs
- Navigate to a real website first

### Extension not appearing
- Make sure you loaded the correct `extension` folder
- Check `chrome://extensions/` for errors
- Ensure `manifest.json` is valid JSON

### Scan takes too long
- Some domains may have slow WHOIS servers
- crt.sh can be slow for domains with many subdomains
- Check your internet connection

---

## 📝 License

MIT License - Feel free to modify and use for security research.

---

## 🔒 Disclaimer

This tool is intended for **authorized security research only**. Only scan domains you own or have explicit permission to analyze. The authors are not responsible for misuse.

---

**SPECTRE v1.0** 
