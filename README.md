# PhishGuard

PhishGuard is a phishing detection system leveraging Machine Learning and external threat intelligence (VirusTotal, URLhaus) with real-time domain forensics (WHOIS, DNS, typosquatting).

### Components
1. **Machine Learning Pipeline**: XGBoost model trained on phishing and legitimate URLs.
2. **FastAPI Backend**: Serves the model and runs parallel forensics.
3. **React Dashboard**: Web interface for analysts to review scans and IoCs.
4. **Chrome Extension**: Real-time browser scanning.

---

## 1. Setup & Installation

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
# source venv/bin/activate

pip install -r backend/requirements.txt

cp backend/.env.example backend/.env
# Add your VirusTotal API key to backend/.env
```

## 2. Download Datasets

Place the following datasets in `ml/data/`:
1. **ISCX URL 2016**: [Link](https://www.kaggle.com/datasets/teseract/urldataset) -> `ml/data/iscx_url_2016.csv`
2. **Tranco Top 1M**: [Link](https://tranco-list.eu/) -> `ml/data/tranco_top1m.csv`

## 3. Train the Model

```bash
python ml/train.py
```
This generates `model.pkl` and `features.json` in the `ml/` directory.

## 4. Run the Backend

```bash
python backend/main.py
```
The FastAPI server will start on `http://0.0.0.0:8000`.

## 5. Run the Dashboard

```bash
cd dashboard
npm install
npm run dev
```

## 6. Chrome Extension

1. Go to `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` directory.

