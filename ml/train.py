import os
import sys
import json
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
from feature_extractor import extract_features

_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_JSON_PATH = os.path.join(_DIR, 'features.json')
MODEL_OUTPUT_PATH = os.path.join(_DIR, 'model.pkl')
ACCURACY_TARGET = 0.95

# ──────────────────────────────────────────────────────────────
# Dataset loaders
# ──────────────────────────────────────────────────────────────

def load_iscx(path: str) -> pd.DataFrame:
    """
    ISCX-URL-2016: columns = [url, type]
    type ∈ {benign, phishing, malware, defacement}
    ALL non-benign types are malicious → label=1
    """
    df = pd.read_csv(path)
    df = df[['url', 'type']].copy()
    df.dropna(subset=['url', 'type'], inplace=True)
    # Normalise type to lowercase and strip whitespace
    df['type'] = df['type'].str.strip().str.lower()
    # benign=0, everything else (phishing, malware, defacement, spam)=1
    df['label'] = (df['type'] != 'benign').astype(int)
    df['source'] = 'iscx'
    return df[['url', 'label', 'source']]


def load_phishtank(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
        if 'url' in df.columns:
            df = df[['url']].copy()
        else:
            df = pd.DataFrame({'url': df.iloc[:, 1]})
        df.dropna(subset=['url'], inplace=True)
        df['label'] = 1
        df['source'] = 'phishtank'
        return df[['url', 'label', 'source']]
    except Exception as e:
        print(f'[!] Failed to load PhishTank: {e}')
        return pd.DataFrame(columns=['url', 'label', 'source'])


def load_urlhaus(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, comment='#', header=None,
                         names=['id', 'dateadded', 'url', 'url_status',
                                'last_online', 'threat', 'tags',
                                'urlhaus_link', 'reporter'],
                         quotechar='"')
        df = df[['url']].dropna().copy()
        df['label'] = 1
        df['source'] = 'urlhaus'
        return df[['url', 'label', 'source']]
    except Exception as e:
        print(f'[!] Failed to load URLHaus: {e}')
        return pd.DataFrame(columns=['url', 'label', 'source'])


def load_tranco(path: str, prefix: str = 'https://') -> pd.DataFrame:
    """
    Tranco Top-1M: columns = [rank, domain]
    All domains are safe → label=0
    We add realistic path/query variations to improve generalisation.
    """
    import random
    random.seed(42)
    df = pd.read_csv(path, header=None, names=['rank', 'domain'])
    urls = []
    paths = ['/', '/index.html', '/about', '/contact', '/products',
             '/login', '/search', '/help', '/privacy', '/terms']
    params = ['?id=123', '?ref=homepage', '?utm_source=internal',
              '?lang=en', '?page=1', '']
    for domain in df['domain']:
        url = prefix + domain
        if random.random() > 0.5:
            url += random.choice(paths)
            url += random.choice(params)
        urls.append(url)
    df['url'] = urls
    df['label'] = 0
    df['source'] = 'tranco'
    return df[['url', 'label', 'source']]


# ──────────────────────────────────────────────────────────────
# Combine all datasets
# ──────────────────────────────────────────────────────────────

def load_and_combine(data_dir: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    iscx_path = os.path.join(data_dir, 'iscx_url_2016.csv')
    tranco_path = os.path.join(data_dir, 'tranco_top1m.csv')
    phishtank_path = os.path.join(data_dir, 'phishtank.csv')
    urlhaus_path = os.path.join(data_dir, 'urlhaus.csv')

    if os.path.isfile(iscx_path):
        print(f'[+] Loading ISCX-URL-2016 from {iscx_path}')
        iscx_df = load_iscx(iscx_path)
        print(f'    → {len(iscx_df)} rows  '
              f'(benign={len(iscx_df[iscx_df.label==0])}, '
              f'malicious={len(iscx_df[iscx_df.label==1])})')
        frames.append(iscx_df)
    else:
        print(f'[!] ISCX-URL-2016 not found at {iscx_path} — skipping')

    if os.path.isfile(phishtank_path):
        print(f'[+] Loading PhishTank from {phishtank_path}')
        pt_df = load_phishtank(phishtank_path)
        if not pt_df.empty:
            print(f'    → {len(pt_df)} malicious URLs')
            frames.append(pt_df)
    else:
        print(f'[!] PhishTank not found at {phishtank_path} — skipping')

    if os.path.isfile(urlhaus_path):
        print(f'[+] Loading URLHaus from {urlhaus_path}')
        uh_df = load_urlhaus(urlhaus_path)
        if not uh_df.empty:
            print(f'    → {len(uh_df)} malicious URLs')
            frames.append(uh_df)
    else:
        print(f'[!] URLHaus not found at {urlhaus_path} — skipping')

    if os.path.isfile(tranco_path):
        print(f'[+] Loading Tranco Top-1M from {tranco_path}')
        tranco_df = load_tranco(tranco_path)
        print(f'    → {len(tranco_df)} safe URLs')
        frames.append(tranco_df)
    else:
        print(f'[!] Tranco Top-1M not found at {tranco_path} — skipping')

    if not frames:
        print('[ERROR] No datasets found.')
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    combined.drop_duplicates(subset='url', inplace=True)
    print(f'\n[*] Combined (deduped): {len(combined)} URLs')
    print(f'    Label distribution: '
          f'safe={len(combined[combined.label==0])}, '
          f'malicious={len(combined[combined.label==1])}')
    return combined


# ──────────────────────────────────────────────────────────────
# Smart class balancing
# ──────────────────────────────────────────────────────────────

def balance_classes(df: pd.DataFrame, max_per_class: int = 200_000) -> pd.DataFrame:
    """
    Balance classes with controlled sampling.
    - Cap each class at max_per_class to keep training time manageable
    - Use 1:1 ratio for optimal XGBoost performance
    """
    phishing = df[df['label'] == 1]
    legit = df[df['label'] == 0]

    print(f'\n[*] Before balancing: {len(phishing)} malicious, {len(legit)} safe')

    # Target count: min(minority, max_per_class)
    target_count = min(len(phishing), len(legit), max_per_class)

    phishing_bal = phishing.sample(n=target_count, random_state=42)
    legit_bal = legit.sample(n=target_count, random_state=42)

    balanced = pd.concat([phishing_bal, legit_bal], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f'[*] After balancing : {target_count} malicious, {target_count} safe')
    print(f'[*] Total training samples: {len(balanced)}')
    return balanced


# ──────────────────────────────────────────────────────────────
# Feature extraction (parallelisable)
# ──────────────────────────────────────────────────────────────

def build_feature_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    print('\n[*] Extracting features from URLs …')
    start = time.time()
    records: list[dict] = []
    total = len(df)
    failed = 0

    for idx, row in df.iterrows():
        try:
            feats = extract_features(row['url'])
        except Exception:
            feats = {}
            failed += 1
        feats['label'] = row['label']
        records.append(feats)
        if (idx + 1) % 20000 == 0 or idx + 1 == total:
            elapsed = time.time() - start
            rate = (idx + 1) / elapsed if elapsed > 0 else 0
            print(f'    {idx + 1:>8} / {total}  ({elapsed:.1f}s, {rate:.0f} URLs/s)')

    feature_df = pd.DataFrame(records)
    feature_df.fillna(0, inplace=True)

    if failed > 0:
        print(f'[!] {failed} URLs failed feature extraction (filled with 0s)')
    print(f'[+] Feature extraction complete: {len(feature_df)} rows × '
          f'{len(feature_df.columns) - 1} features')
    return feature_df


# ──────────────────────────────────────────────────────────────
# Feature order persistence
# ──────────────────────────────────────────────────────────────

def save_feature_order(columns: list[str]) -> None:
    payload = {
        '_FILE': 'features.json',
        '_PURPOSE': 'Ordered list of feature columns — MUST match model.pkl',
        '_CONNECTS_TO': 'ml/feature_extractor.py, ml/train.py',
        'features': columns
    }
    with open(FEATURES_JSON_PATH, 'w') as f:
        json.dump(payload, f, indent=2)
    print(f'\n[+] Feature order saved to {FEATURES_JSON_PATH}')
    print(f'    Columns ({len(columns)}): {columns}')


# ──────────────────────────────────────────────────────────────
# Training pipeline
# ──────────────────────────────────────────────────────────────

def train(feature_df: pd.DataFrame) -> None:
    feature_cols = [c for c in feature_df.columns if c != 'label']
    X = feature_df[feature_cols]
    y = feature_df['label']

    save_feature_order(feature_cols)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f'\n[*] Training set : {len(X_train)} samples')
    print(f'[*] Test set     : {len(X_test)} samples')
    print(f'[*] Features     : {len(feature_cols)}')

    # ── XGBoost with tuned hyperparameters ──
    model = XGBClassifier(
        n_estimators=800,
        max_depth=10,
        learning_rate=0.03,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        reg_alpha=0.1,          # L1 regularisation
        reg_lambda=1.5,         # L2 regularisation
        min_child_weight=5,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,              # min split loss
        tree_method='hist',     # fast histogram-based method
        early_stopping_rounds=30,
    )

    print('\n[*] Training XGBoost (n_estimators=800, max_depth=10, lr=0.03) …')
    start = time.time()

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    elapsed = time.time() - start
    print(f'[+] Training complete in {elapsed:.1f}s')
    print(f'[+] Best iteration: {model.best_iteration}')

    # ── Evaluation ──
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

    # ── Feature importance (top 15) ──
    importances = model.feature_importances_
    importance_df = pd.DataFrame({
        'feature': feature_cols,
        'importance': importances
    }).sort_values('importance', ascending=False)
    print('  Top 15 Feature Importances:')
    print('  ' + '-' * 45)
    for _, row in importance_df.head(15).iterrows():
        bar = '█' * int(row['importance'] * 100)
        print(f'    {row["feature"]:30s}  {row["importance"]:.4f}  {bar}')
    print()

    # ── Inference speed test ──
    print('[*] Running inference speed test (1000 predictions) …')
    speed_X = X_test.head(1000) if len(X_test) >= 1000 else X_test
    speed_start = time.time()
    for _ in range(10):
        _ = model.predict(speed_X)
    speed_elapsed = (time.time() - speed_start) / 10
    per_sample_ms = (speed_elapsed / len(speed_X)) * 1000
    print(f'  Batch of {len(speed_X)}: {speed_elapsed*1000:.1f} ms total')
    print(f'  Per-sample inference: {per_sample_ms:.3f} ms')
    print()

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
    print('  PhishGuard — ML Training Pipeline v2')
    print('  35 features · XGBoost · 4 datasets')
    print('=' * 60)

    raw_df = load_and_combine(data_dir)
    balanced_df = balance_classes(raw_df)
    feature_df = build_feature_dataframe(balanced_df)
    train(feature_df)

    print('\n[DONE] Pipeline complete.')


if __name__ == '__main__':
    main()