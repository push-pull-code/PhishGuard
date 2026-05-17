# PhishGuard 🛡️

PhishGuard is a high-performance browser extension and machine learning pipeline designed for real-time phishing detection. It uses a hybrid approach of ML inference, dataset matching (OpenPhish, ISCX, URLhaus, Tranco), and domain forensics (WHOIS, DNS, Typosquatting) to classify URLs in under 500ms.

## Architecture
- **Frontend:** Chrome Extension (`manifest V3`, Vanilla JS/HTML/Tailwind) with an IndexedDB client-side cache and auto-scan background worker.
- **Backend:** Python FastAPI server with an LRU cache, dataset lookup service (O(1) hash-map matching), and parallelized external intel gathering.
- **ML Pipeline:** XGBoost classifier utilizing 22 URL features (entropy, digit ratios, path depths, etc).

## Installation

### 1. Setup the Backend
Make sure you have Python 3.9+ installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the dependencies
pip install -r requirements.txt
```

### 2. Download Datasets and Train Model (Optional)
If you want to train the model from scratch, place your CSV datasets (`iscx_url_2016.csv`, `urlhaus.csv`, `phishtank.csv`, `tranco_top1m.csv`) into the `ml/data/` folder and run:
```bash
python ml/train.py
```
*(A pre-trained `model.pkl` is already built into the pipeline).*

### 3. Run the API Server
Start the FastAPI server:
```bash
python backend/main.py
```
The server will run at `http://localhost:8000`.

### 4. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** in the top right corner.
3. Click **Load unpacked** and select the `extension/` folder in this repository.
4. Pin the PhishGuard icon to your toolbar.

## Usage
The extension automatically monitors pages you navigate to and changes color to indicate safety:
- 🟢 **Green**: Safe / Genuine
- 🟠 **Orange**: Suspicious / Caution
- 🔴 **Red**: Phishing / Malware
- ⚪ **Grey**: Inactive / Internal page

Click the extension icon at any time to see a detailed breakdown of the threat score, ML confidence, and domain forensics.

## Cache Management
To clear the backend in-memory cache:
```bash
curl -X DELETE http://localhost:8000/scan/cache
```
To clear the extension cache for a single URL, click the **Rescan** button in the popup.
