# FILE: train.py
# PURPOSE: Complete XGBoost training pipeline — loads datasets, extracts features, trains, evaluates, and saves the model
# CONNECTS TO: ml/feature_extractor.py, ml/features.json, ml/model.pkl

# ---------------------------------------------------------------------------
# WHAT IS XGBOOST vs RANDOM FOREST?
# ---------------------------------------------------------------------------
# Both are ensemble methods that combine many decision trees, but they differ
# in *how* the trees are built:
#
#   Random Forest  → trains N trees INDEPENDENTLY on random subsets of the
#                    data (bagging), then averages their votes.  Simple, hard
#                    to overfit, but each tree ignores the mistakes of others.
#
#   XGBoost        → trains trees SEQUENTIALLY.  Each new tree focuses on the
#                    errors the previous ensemble still makes (gradient
#                    boosting).  This "learn from mistakes" loop usually
#                    reaches higher accuracy with fewer trees, at the cost of
#                    being more sensitive to hyperparameters and overfitting.
#
# For phishing detection XGBoost typically wins because our feature space is
# small (~10 features) and the boosting loop squeezes out extra signal that
# bagging would miss.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# WHAT IS A BALANCED DATASET AND WHY DOES IT MATTER?
# ---------------------------------------------------------------------------
# A balanced dataset has roughly equal numbers of positive (phishing) and
# negative (legitimate) samples.
#
# WHY IT MATTERS:
#   If we train on 95% legit + 5% phishing, the model can simply predict
#   "legit" every time and achieve 95% accuracy — but it catches ZERO
#   phishing URLs.  That metric is meaningless.  Balancing ensures the
#   model must actually learn the difference between classes to score well.
#   After balancing, accuracy, precision, recall, and F1 all become
#   meaningful indicators of real-world performance.
# ---------------------------------------------------------------------------

import os
import sys
import json
import time

import pandas as pd                # tabular data handling
import joblib                      # efficient model serialization

# sklearn — evaluation utilities
from sklearn.model_selection import train_test_split  # splits data into train/test sets randomly
from sklearn.metrics import (
    accuracy_score,          # (correct predictions) / (total predictions)
    precision_score,         # (true positives) / (true positives + false positives)
    recall_score,            # (true positives) / (true positives + false negatives)
    f1_score,                # harmonic mean of precision & recall — single balanced metric
    confusion_matrix,        # 2×2 matrix: [[TN, FP], [FN, TP]]
    classification_report,   # pretty-printed table of all per-class metrics
)

# XGBoost classifier
from xgboost import XGBClassifier  # gradient-boosted decision tree ensemble

# Our own feature extractor (same folder)
from feature_extractor import extract_features

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_JSON_PATH = os.path.join(_DIR, "features.json")
MODEL_OUTPUT_PATH = os.path.join(_DIR, "model.pkl")
ACCURACY_TARGET = 0.95


# =====================================================================
# DATASET LOADING
# =====================================================================
# DOWNLOAD INSTRUCTIONS (do these ONCE, place CSVs in ml/data/):
#
# 1. ISCX-URL-2016 (Kaggle)
#    → https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
#    → Download "dataset.csv".  Columns: "url", "type"
#      (type values: benign, defacement, phishing, malware)
#    → Save as:  ml/data/iscx_url_2016.csv
#
# 2. PhishTank (verified online phishing URLs)
#    → https://phishtank.org/developer_info.php
#    → Register for a free API key, then download the CSV feed.
#      The file contains columns including "url" and "verified".
#    → Save as:  ml/data/phishtank.csv
#
# 3. Tranco Top 1M (legitimate / popular domains)
#    → https://tranco-list.eu/
#    → Click "Download list".  CSV columns: rank, domain
#    → Save as:  ml/data/tranco_top1m.csv
# =====================================================================


def load_iscx(path: str) -> pd.DataFrame:
    """Load the ISCX-URL-2016 dataset and normalise to (url, label) format.

    Labels: phishing → 1, everything else → 0.
    """
    # read_csv: parses a comma-separated file into a DataFrame
    df = pd.read_csv(path)
    df = df[["url", "type"]].copy()

    # Map the multi-class "type" column to binary: phishing=1, rest=0
    df["label"] = (df["type"] == "phishing").astype(int)
    return df[["url", "label"]]


def load_phishtank(path: str) -> pd.DataFrame:
    """Load PhishTank CSV — every row is a verified phishing URL (label=1)."""
    df = pd.read_csv(path)

    # PhishTank columns vary; the URL column is usually named "url"
    url_col = "url" if "url" in df.columns else df.columns[0]
    df = df[[url_col]].rename(columns={url_col: "url"})
    df["label"] = 1
    return df[["url", "label"]]


def load_tranco(path: str, prefix: str = "https://") -> pd.DataFrame:
    """Load Tranco Top-1M as legitimate URLs (label=0).

    Tranco only provides bare domains. To fix dataset bias (where the model
    thinks only bare domains are legitimate), we randomly append common
    paths and query parameters to 50% of the URLs.
    """
    import random
    random.seed(42)

    df = pd.read_csv(path, header=None, names=["rank", "domain"])
    urls = []

    # Common "safe" paths and parameters to inject variety
    paths = ["/", "/index.html", "/about", "/contact", "/products", "/login", "/search"]
    params = ["?id=123", "?ref=homepage", "?utm_source=internal", "?lang=en", ""]

    for domain in df["domain"]:
        url = prefix + domain
        # 50% chance to add complexity
        if random.random() > 0.5:
            url += random.choice(paths)
            url += random.choice(params)
        urls.append(url)

    df["url"] = urls
    df["label"] = 0
    return df[["url", "label"]]


def load_and_combine(data_dir: str) -> pd.DataFrame:
    """Discover available datasets in *data_dir*, load them, and combine.

    Falls back gracefully if a file is missing — prints a warning and
    continues with whatever data is available.
    """
    frames: list[pd.DataFrame] = []

    iscx_path = os.path.join(data_dir, "iscx_url_2016.csv")
    phishtank_path = os.path.join(data_dir, "phishtank.csv")
    tranco_path = os.path.join(data_dir, "tranco_top1m.csv")

    if os.path.isfile(iscx_path):
        print(f"[+] Loading ISCX-URL-2016 from {iscx_path}")
        frames.append(load_iscx(iscx_path))
    else:
        print(f"[!] ISCX-URL-2016 not found at {iscx_path} — skipping")

    if os.path.isfile(phishtank_path):
        print(f"[+] Loading PhishTank from {phishtank_path}")
        frames.append(load_phishtank(phishtank_path))
    else:
        print(f"[!] PhishTank not found at {phishtank_path} — skipping")

    if os.path.isfile(tranco_path):
        print(f"[+] Loading Tranco Top-1M from {tranco_path}")
        frames.append(load_tranco(tranco_path))
    else:
        print(f"[!] Tranco Top-1M not found at {tranco_path} — skipping")

    if not frames:
        print("[ERROR] No datasets found.  See the DOWNLOAD INSTRUCTIONS at")
        print("        the top of this file, place CSVs in ml/data/, then re-run.")
        sys.exit(1)

    # concat: vertically stacks multiple DataFrames into one
    combined = pd.concat(frames, ignore_index=True)

    # drop_duplicates: removes rows where the URL appears more than once
    combined.drop_duplicates(subset="url", inplace=True)

    return combined


# =====================================================================
# CLASS BALANCING
# =====================================================================

def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    """Downsample the majority class so both classes have equal size.

    This prevents the model from achieving high accuracy by simply
    predicting the majority class for every input.
    """
    phishing = df[df["label"] == 1]
    legit = df[df["label"] == 0]

    minority_count = min(len(phishing), len(legit))

    print(f"\n[*] Before balancing: {len(phishing)} phishing, {len(legit)} legit")

    # sample: randomly selects *n* rows without replacement
    phishing_bal = phishing.sample(n=minority_count, random_state=42)
    legit_bal = legit.sample(n=minority_count, random_state=42)

    balanced = pd.concat([phishing_bal, legit_bal], ignore_index=True)

    # shuffle so the model doesn't see all phishing then all legit
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"[*] After balancing : {minority_count} phishing, {minority_count} legit")
    print(f"[*] Total training samples: {len(balanced)}")

    return balanced


# =====================================================================
# FEATURE MATRIX CONSTRUCTION
# =====================================================================

def build_feature_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Run extract_features() on every URL and build a feature DataFrame.

    Also retains the original 'label' column.
    """
    print("\n[*] Extracting features from URLs …")
    start = time.time()

    records: list[dict] = []
    total = len(df)

    for idx, row in df.iterrows():
        try:
            feats = extract_features(row["url"])
        except Exception:
            # If a single URL fails, fill with zeros rather than crashing
            feats = {}

        feats["label"] = row["label"]
        records.append(feats)

        # Progress indicator every 10 000 rows
        if (idx + 1) % 10_000 == 0 or idx + 1 == total:
            elapsed = time.time() - start
            print(f"    {idx + 1:>8} / {total}  ({elapsed:.1f}s)")

    # DataFrame constructor: converts list-of-dicts → columnar table
    feature_df = pd.DataFrame(records)

    # fillna: replaces NaN (from missing keys) with 0
    feature_df.fillna(0, inplace=True)

    return feature_df


# =====================================================================
# SAVE FEATURE COLUMN ORDER
# =====================================================================

# WARNING: features.json and model.pkl MUST stay in sync.
# The model was trained on columns in a specific order.  At inference time
# the same column order must be used, otherwise feature values get fed into
# the wrong tree splits and predictions become meaningless garbage.
# ALWAYS re-save features.json when you retrain the model.

def save_feature_order(columns: list[str]) -> None:
    """Persist the feature column names and order to features.json."""
    payload = {
        "_FILE": "features.json",
        "_PURPOSE": "Ordered list of feature columns — MUST match model.pkl",
        "_CONNECTS_TO": "ml/feature_extractor.py, ml/train.py",
        "features": columns,
    }
    with open(FEATURES_JSON_PATH, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[+] Feature order saved to {FEATURES_JSON_PATH}")
    print(f"    Columns ({len(columns)}): {columns}")


# =====================================================================
# TRAINING
# =====================================================================

def train(feature_df: pd.DataFrame) -> None:
    """Train an XGBClassifier, evaluate it, and save the model artefact."""

    # Separate feature matrix (X) from target labels (y)
    feature_cols = [c for c in feature_df.columns if c != "label"]
    X = feature_df[feature_cols]
    y = feature_df["label"]

    # CRITICAL: save the column order BEFORE training so inference uses the
    #           exact same order of features.
    save_feature_order(feature_cols)

    # train_test_split: randomly assigns 80% of rows to training and 20% to
    #   testing.  stratify=y ensures both splits keep the same class ratio.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y,        # keeps 50/50 balance in both splits
    )

    print(f"\n[*] Training set : {len(X_train)} samples")
    print(f"[*] Test set     : {len(X_test)} samples")

    # ------------------------------------------------------------------
    # Build the XGBoost model
    # ------------------------------------------------------------------
    # XGBClassifier parameters:
    #   n_estimators  — number of boosting rounds (trees to build sequentially)
    #   max_depth     — max depth per tree; deeper = more complex but risk overfit
    #   learning_rate — shrinks each tree's contribution; smaller = more robust
    #   eval_metric   — loss function to monitor during training
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )

    print("\n[*] Training XGBoost (n_estimators=200, max_depth=6) …")
    start = time.time()

    # fit: the core training call — iteratively builds boosted trees on
    #      (X_train, y_train) and monitors progress on the eval set.
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    elapsed = time.time() - start
    print(f"[+] Training complete in {elapsed:.1f}s")

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    # predict: runs the trained ensemble on unseen test data to produce
    #          class labels (0 or 1).
    y_pred = model.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    cm   = confusion_matrix(y_test, y_pred)

    # EXPECTED: Good vs bad metrics for phishing detection
    # ┌────────────┬────────────────────────────────┬────────────────────────────────────┐
    # │ Metric     │ GOOD (production-ready)        │ BAD (needs work)                   │
    # ├────────────┼────────────────────────────────┼────────────────────────────────────┤
    # │ Accuracy   │ ≥ 0.95                         │ < 0.90                             │
    # │ Precision  │ ≥ 0.95 (few false alarms)      │ < 0.85 (too many false positives)  │
    # │ Recall     │ ≥ 0.93 (catches most phishing) │ < 0.85 (missing real phishing)     │
    # │ F1         │ ≥ 0.94                         │ < 0.85                             │
    # └────────────┴────────────────────────────────┴────────────────────────────────────┘
    # For a security tool, recall matters most — a missed phishing URL is
    # far more dangerous than a false alarm on a legit site.

    print("\n" + "=" * 60)
    print("  EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print()
    print("  Confusion Matrix:")
    print(f"    TN={cm[0][0]:>6}   FP={cm[0][1]:>6}")
    print(f"    FN={cm[1][0]:>6}   TP={cm[1][1]:>6}")
    print()

    # classification_report: a convenience wrapper that prints precision,
    #   recall, F1, and support for each class in a readable table.
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    # ------------------------------------------------------------------
    # Accuracy gate
    # ------------------------------------------------------------------
    if acc >= ACCURACY_TARGET:
        print(f"[PASS] Accuracy {acc:.4f} meets the >={ACCURACY_TARGET} target!")
    else:
        print(f"[FAIL] Accuracy {acc:.4f} is BELOW the >={ACCURACY_TARGET} target.")
        print()
        print("  SUGGESTIONS TO IMPROVE:")
        print("  1. Add more training data — especially diverse phishing samples")
        print("     from PhishTank + OpenPhish + ISCX.")
        print("  2. Engineer more features — e.g. WHOIS age, page-content")
        print("     similarity, redirect-chain depth.")
        print("  3. Tune hyperparameters — try n_estimators=500, max_depth=8,")
        print("     learning_rate=0.05, add regularisation (reg_alpha, reg_lambda).")
        print("  4. Use cross-validation (sklearn.model_selection.cross_val_score)")
        print("     instead of a single train/test split for more stable estimates.")
        print("  5. Inspect the confusion matrix: if FN is high, the model needs")
        print("     more phishing examples or a lower classification threshold.")

    # ------------------------------------------------------------------
    # Save model
    # ------------------------------------------------------------------

    # joblib.dump: serialises the trained model to disk as a compressed
    #   pickle file.  joblib is preferred over plain pickle for numpy-heavy
    #   objects because it handles large arrays more efficiently.
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\n[+] Model saved to {MODEL_OUTPUT_PATH}")

    # WARNING: If you later modify extract_features() to add/remove/reorder
    # columns but forget to retrain, model.pkl and features.json will be out
    # of sync.  The model will silently consume wrong feature values and
    # produce garbage predictions.  ALWAYS retrain after changing features.


# =====================================================================
# ENTRY POINT
# =====================================================================

def main():
    """CLI entry point.

    Usage:
        python train.py                   # uses default ml/data/ directory
        python train.py path/to/data/     # custom data directory
    """
    data_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_DIR, "data")

    print("=" * 60)
    print("  PhishGuard — ML Training Pipeline")
    print("=" * 60)

    # Step 1: Load & combine datasets
    raw_df = load_and_combine(data_dir)

    # Step 2: Balance classes
    balanced_df = balance_classes(raw_df)

    # Step 3: Extract features → build feature DataFrame
    feature_df = build_feature_dataframe(balanced_df)

    # Step 4-7: Train, evaluate, save
    train(feature_df)

    print("\n[PASS] Pipeline complete.")


if __name__ == "__main__":
    main()
