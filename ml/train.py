import os
import sys
import json
import time
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
from feature_extractor import extract_features
_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_JSON_PATH = os.path.join(_DIR, 'features.json')
MODEL_OUTPUT_PATH = os.path.join(_DIR, 'model.pkl')
ACCURACY_TARGET = 0.95

def load_iscx(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[['url', 'type']].copy()
    df['label'] = (df['type'] == 'phishing').astype(int)
    return df[['url', 'label']]

def load_phishtank(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
        if 'url' in df.columns:
            df = df[['url']].copy()
        else:
            df = pd.DataFrame({'url': df.iloc[:, 1]})
        df['label'] = 1
        return df[['url', 'label']]
    except Exception as e:
        print(f'[!] Failed to load PhishTank: {e}')
        return pd.DataFrame(columns=['url', 'label'])

def load_urlhaus(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, comment='#', header=None, names=['id','dateadded','url','url_status','last_online','threat','tags','urlhaus_link','reporter'], quotechar='"')
        df = df[['url']].dropna().copy()
        df['label'] = 1
        return df[['url', 'label']]
    except Exception as e:
        print(f'[!] Failed to load URLHaus: {e}')
        return pd.DataFrame(columns=['url', 'label'])

def load_tranco(path: str, prefix: str='https://') -> pd.DataFrame:
    import random
    random.seed(42)
    df = pd.read_csv(path, header=None, names=['rank', 'domain'])
    urls = []
    paths = ['/', '/index.html', '/about', '/contact', '/products', '/login', '/search']
    params = ['?id=123', '?ref=homepage', '?utm_source=internal', '?lang=en', '']
    for domain in df['domain']:
        url = prefix + domain
        if random.random() > 0.5:
            url += random.choice(paths)
            url += random.choice(params)
        urls.append(url)
    df['url'] = urls
    df['label'] = 0
    return df[['url', 'label']]

def load_and_combine(data_dir: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    iscx_path = os.path.join(data_dir, 'iscx_url_2016.csv')
    tranco_path = os.path.join(data_dir, 'tranco_top1m.csv')
    phishtank_path = os.path.join(data_dir, 'phishtank.csv')
    urlhaus_path = os.path.join(data_dir, 'urlhaus.csv')
    if os.path.isfile(iscx_path):
        print(f'[+] Loading ISCX-URL-2016 from {iscx_path}')
        frames.append(load_iscx(iscx_path))
    else:
        print(f'[!] ISCX-URL-2016 not found at {iscx_path} — skipping')
    
    if os.path.isfile(phishtank_path):
        print(f'[+] Loading PhishTank from {phishtank_path}')
        pt_df = load_phishtank(phishtank_path)
        if not pt_df.empty: frames.append(pt_df)
    else:
        print(f'[!] PhishTank not found at {phishtank_path} — skipping')
        
    if os.path.isfile(urlhaus_path):
        print(f'[+] Loading URLHaus from {urlhaus_path}')
        uh_df = load_urlhaus(urlhaus_path)
        if not uh_df.empty: frames.append(uh_df)
    else:
        print(f'[!] URLHaus not found at {urlhaus_path} — skipping')

    if os.path.isfile(tranco_path):
        print(f'[+] Loading Tranco Top-1M from {tranco_path}')
        frames.append(load_tranco(tranco_path))
    else:
        print(f'[!] Tranco Top-1M not found at {tranco_path} — skipping')
    if not frames:
        print('[ERROR] No datasets found.  See the DOWNLOAD INSTRUCTIONS at')
        print('        the top of this file, place CSVs in ml/data/, then re-run.')
        sys.exit(1)
    combined = pd.concat(frames, ignore_index=True)
    combined.drop_duplicates(subset='url', inplace=True)
    return combined

def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    phishing = df[df['label'] == 1]
    legit = df[df['label'] == 0]
    minority_count = min(len(phishing), len(legit))
    print(f'\n[*] Before balancing: {len(phishing)} phishing, {len(legit)} legit')
    phishing_bal = phishing.sample(n=minority_count, random_state=42)
    legit_bal = legit.sample(n=minority_count, random_state=42)
    balanced = pd.concat([phishing_bal, legit_bal], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f'[*] After balancing : {minority_count} phishing, {minority_count} legit')
    print(f'[*] Total training samples: {len(balanced)}')
    return balanced

def build_feature_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    print('\n[*] Extracting features from URLs …')
    start = time.time()
    records: list[dict] = []
    total = len(df)
    for idx, row in df.iterrows():
        try:
            feats = extract_features(row['url'])
        except Exception:
            feats = {}
        feats['label'] = row['label']
        records.append(feats)
        if (idx + 1) % 10000 == 0 or idx + 1 == total:
            elapsed = time.time() - start
            print(f'    {idx + 1:>8} / {total}  ({elapsed:.1f}s)')
    feature_df = pd.DataFrame(records)
    feature_df.fillna(0, inplace=True)
    return feature_df

def save_feature_order(columns: list[str]) -> None:
    payload = {'_FILE': 'features.json', '_PURPOSE': 'Ordered list of feature columns — MUST match model.pkl', '_CONNECTS_TO': 'ml/feature_extractor.py, ml/train.py', 'features': columns}
    with open(FEATURES_JSON_PATH, 'w') as f:
        json.dump(payload, f, indent=2)
    print(f'\n[+] Feature order saved to {FEATURES_JSON_PATH}')
    print(f'    Columns ({len(columns)}): {columns}')

def train(feature_df: pd.DataFrame) -> None:
    feature_cols = [c for c in feature_df.columns if c != 'label']
    X = feature_df[feature_cols]
    y = feature_df['label']
    save_feature_order(feature_cols)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f'\n[*] Training set : {len(X_train)} samples')
    print(f'[*] Test set     : {len(X_test)} samples')
    model = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, use_label_encoder=False, eval_metric='logloss', random_state=42)
    print('\n[*] Training XGBoost (n_estimators=200, max_depth=6) …')
    start = time.time()
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
    elapsed = time.time() - start
    print(f'[+] Training complete in {elapsed:.1f}s')
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    print('\n' + '=' * 60)
    print('  EVALUATION RESULTS')
    print('=' * 60)
    print(f'  Accuracy  : {acc:.4f}')
    print(f'  Precision : {prec:.4f}')
    print(f'  Recall    : {rec:.4f}')
    print(f'  F1 Score  : {f1:.4f}')
    print()
    print('  Confusion Matrix:')
    print(f'    TN={cm[0][0]:>6}   FP={cm[0][1]:>6}')
    print(f'    FN={cm[1][0]:>6}   TP={cm[1][1]:>6}')
    print()
    print(classification_report(y_test, y_pred, target_names=['legit', 'phishing']))
    if acc >= ACCURACY_TARGET:
        print(f'[PASS] Accuracy {acc:.4f} meets the >={ACCURACY_TARGET} target!')
    else:
        print(f'[FAIL] Accuracy {acc:.4f} is BELOW the >={ACCURACY_TARGET} target.')
        print()
        print('  SUGGESTIONS TO IMPROVE:')
        print('  1. Add more training data — especially diverse phishing samples')
        print('     from OpenPhish + ISCX.')
        print('  2. Engineer more features — e.g. WHOIS age, page-content')
        print('     similarity, redirect-chain depth.')
        print('  3. Tune hyperparameters — try n_estimators=500, max_depth=8,')
        print('     learning_rate=0.05, add regularisation (reg_alpha, reg_lambda).')
        print('  4. Use cross-validation (sklearn.model_selection.cross_val_score)')
        print('     instead of a single train/test split for more stable estimates.')
        print('  5. Inspect the confusion matrix: if FN is high, the model needs')
        print('     more phishing examples or a lower classification threshold.')
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f'\n[+] Model saved to {MODEL_OUTPUT_PATH}')

def main():
    data_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_DIR, 'data')
    print('=' * 60)
    print('  PhishGuard — ML Training Pipeline')
    print('=' * 60)
    raw_df = load_and_combine(data_dir)
    balanced_df = balance_classes(raw_df)
    feature_df = build_feature_dataframe(balanced_df)
    train(feature_df)
    print('\n[PASS] Pipeline complete.')
if __name__ == '__main__':
    main()