# PhishGuard — Real-Time Phishing Detection

PhishGuard is a full-stack phishing detection system powered by Machine Learning, external threat intelligence (VirusTotal, URLhaus), and real-time domain forensics (WHOIS, DNS, typosquatting).

This repository contains:
1. **Machine Learning Pipeline**: Trains an XGBoost model on known phishing and legitimate URLs.
2. **FastAPI Backend**: Serves the model and runs parallel forensics, returning results in `< 500ms`.
3. **React Dashboard**: A modern web interface for analysts to review scans, indicators of compromise (IoC), and risk distribution.
4. **Chrome Extension**: Scans websites in real-time as you browse.

---

## 1. Setup & Installation

Follow these steps exactly to get your environment ready.
*(Note for beginners: The commands below should be typed into your terminal/command prompt)*

```bash
# Step 1: Create a virtual environment (a sandbox to keep Python packages isolated)
python -m venv venv

# Step 2: Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
# source venv/bin/activate

# Step 3: Install all required Python packages for the backend and ML model
pip install -r backend/requirements.txt

# Step 4: Setup your environment variables
# Copy the example file and add your VirusTotal API key if you have one.
cp backend/.env.example backend/.env
```

---

## 2. Download Datasets

Before you can train the model, you need data! Download these datasets and place them in `ml/data/`.

1. **PhishTank** (Phishing URLs)
   - *Link:* [http://data.phishtank.com/data/online-valid.csv](http://data.phishtank.com/data/online-valid.csv)
   - *Instructions:* Save this file as `ml/data/phishtank.csv`.
2. **ISCX URL 2016** (Mixed URLs)
   - *Link:* [Kaggle - ISCX URL 2016](https://www.kaggle.com/datasets/teseract/urldataset)
   - *Instructions:* Download the CSV and save it as `ml/data/iscx_url_2016.csv`.
3. **Tranco Top 1M** (Legitimate URLs)
   - *Link:* [https://tranco-list.eu/](https://tranco-list.eu/)
   - *Instructions:* Download the top 1M list and save it as `ml/data/tranco_top1m.csv`.

---

## 3. Train the Model

Now that you have the data, you need to train the XGBoost Machine Learning model. The model learns to distinguish between safe and malicious URLs based on features like URL length, entropy, and special characters.

```bash
# Run the training script (make sure your venv is still activated!)
python ml/train.py
```
*What this does:* It will read the CSV files, balance the dataset, extract features, train the XGBoost model, and save `model.pkl` and `features.json` to the `ml/` directory.

---

## 4. Run the Backend Server

The backend serves the ML model via a high-performance FastAPI server.

```bash
# Start the FastAPI server on port 8000
python backend/main.py
```
*What this does:* The server will load the trained `model.pkl` into memory and start listening for URL scan requests. You should see "Uvicorn running on http://0.0.0.0:8000". Leave this terminal window running!

---

## 5. Run the React Dashboard

The dashboard provides a visual interface for analysts.

```bash
# Open a NEW terminal window and navigate to the dashboard folder
cd dashboard

# Install the necessary Node.js packages (you need Node.js installed for this)
npm install

# Start the Vite development server
npm run dev
```
*What this does:* It will give you a local URL (like `http://localhost:5173`). Open that in your browser to use the PhishGuard dashboard.

---

## 6. Load the Chrome Extension

You can use the Chrome extension to scan the website you are currently looking at.

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (the toggle switch in the top right corner).
3. Click the **Load unpacked** button.
4. Select the `extension/` folder inside your PhishGuard project directory.
5. The PhishGuard icon will now appear in your browser toolbar! Click it while on any webpage to scan it.
