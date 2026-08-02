# 🛡️ PhishGuard

PhishGuard is a real-time phishing URL detection system that combines machine learning, browser-based threat intelligence, and asynchronous domain analysis to identify malicious websites with low latency. The system consists of a Chrome Extension (Manifest V3) and a FastAPI backend that performs parallel security lookups before classifying URLs using an ensemble machine learning model.

---

## 🚀 Features

- ⚡ Real-time phishing detection in ~400ms average latency
- 🤖 Soft Voting Ensemble (XGBoost + Random Forest + SVM)
- 🌐 Parallel asynchronous DNS, WHOIS, VirusTotal, URLHaus, and PhishTank lookups
- 📊 36 handcrafted URL-based features for ML inference
- 🧠 Intelligent caching using IndexedDB (client) and LRU Cache (backend)
- 🔄 Request deduplication to avoid redundant external API calls
- 🧩 Chrome Extension built using Manifest V3 Service Workers
- 📈 Threat score with ML confidence and domain intelligence

---

# 🏗️ Architecture

```
Chrome Extension
        │
        ▼
Manifest V3 Service Worker
        │
        ▼
 IndexedDB Cache
        │
        ▼
 FastAPI Backend
        │
 ┌──────┴───────────────────────────┐
 │                                  │
 ▼                                  ▼
Threat Intelligence APIs       Feature Extraction
(DNS, WHOIS, VirusTotal,       (36 URL Features)
 URLHaus, PhishTank)
 │                                  │
 └──────────────┬───────────────────┘
                ▼
     Soft Voting Ensemble
(XGBoost + Random Forest + SVM)
                │
                ▼
      Safe / Suspicious / Phishing
```

---

# 🧠 Machine Learning Pipeline

The phishing classifier uses a **Soft Voting Ensemble** consisting of:

- XGBoost
- Random Forest
- Support Vector Machine (SVM)

The ensemble combines probability outputs from all three models, improving robustness and generalization over relying on a single classifier.

### Feature Engineering

The model is trained on **36 handcrafted URL-based features**, including:

- URL Length
- Domain Length
- Digit Ratio
- Special Character Count
- Path Depth
- Entropy
- Suspicious Keywords
- Number of Subdomains
- HTTPS Usage
- IP Address Presence
- URL Shortener Detection
- Domain Age
- and additional lexical & structural URL features.

---

# ⚡ Threat Intelligence

For every scanned URL, the backend performs asynchronous lookups across multiple intelligence sources:

- DNS Resolution
- WHOIS Records
- VirusTotal
- URLHaus
- PhishTank

These requests execute concurrently using asynchronous FastAPI endpoints, significantly reducing average response latency.

---

# 💾 Caching

## Client Side

- IndexedDB
- Instant lookup for previously scanned URLs
- Rescan option to bypass cache

## Backend

- LRU Cache
- Request Deduplication
- Prevents repeated external API requests for identical URLs

---

# 🖥️ Tech Stack

### Frontend

- Chrome Extension
- Manifest V3
- JavaScript
- HTML
- TailwindCSS

### Backend

- Python
- FastAPI
- AsyncIO

### Machine Learning

- XGBoost
- Random Forest
- Support Vector Machine
- Scikit-Learn
- Pandas
- NumPy

---

# 📂 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard
```

## Create Virtual Environment

```bash
python -m venv .venv
```

Windows

```bash
.venv\Scripts\activate
```

Linux/Mac

```bash
source .venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Run Backend

```bash
python backend/main.py
```

or

```bash
uvicorn main:app --reload
```

Backend

```
http://localhost:8000
```

---

# 🧩 Install Chrome Extension

1. Open Chrome

```
chrome://extensions
```

2. Enable Developer Mode

3. Click **Load Unpacked**

4. Select the `extension/` directory

---

# 📊 Prediction Output

The extension displays

- 🟢 Safe
- 🟠 Suspicious
- 🔴 Phishing

along with

- ML Confidence
- Threat Score
- Domain Intelligence Summary

---

# 📈 Performance

- Average Detection Latency: **~400 ms**
- Parallel asynchronous API requests
- IndexedDB + LRU Cache for low-latency repeated scans
- Soft Voting Ensemble improves classification robustness

---

# 🔮 Future Improvements

- Deep Learning based URL classification
- Browser history risk analysis
- Email phishing detection
- Real-time blacklist synchronization
- Cloud deployment with Docker & Kubernetes
