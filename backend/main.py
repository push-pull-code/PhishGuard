# FILE: main.py
# PURPOSE: FastAPI application entry point — configures middleware, loads ML model at startup, registers routes
# CONNECTS TO: backend/routes/scan.py, backend/routes/health.py, ml/model.pkl, ml/features.json

import os
import sys
import json
import time
import logging

import joblib
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Make the ml/ package importable from backend/
# ---------------------------------------------------------------------------
# We add the project root (one level up from backend/) to sys.path so that
# `from ml.feature_extractor import …` works without installing ml as a package.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from routes import scan, health  # noqa: E402 — must come after sys.path fix

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger("phishguard")

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
# FastAPI() creates the ASGI application object.  All routes, middleware, and
# lifecycle hooks are registered on this object.

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL detection API powered by XGBoost",
    version="1.0.0",
)


# =====================================================================
# CORS MIDDLEWARE
# =====================================================================
# CORSMiddleware tells the browser "yes, requests from these origins are
# allowed".  We permit ALL origins ("*") because:
#   1. The Chrome extension's popup runs on a chrome-extension:// origin
#      that would be blocked by a strict allowlist.
#   2. The React dashboard dev server runs on http://localhost:5173,
#      which is a different origin from the API on :8000.
# In production you would lock this down to specific domains.

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # needed for Chrome extension + React dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# RESPONSE-TIME MIDDLEWARE
# =====================================================================
# This middleware wraps every single request/response cycle and logs how
# many milliseconds the server spent processing it.  It also injects an
# "X-Response-Time-Ms" header into every response so the client can read
# the timing without parsing logs.
#
# # SUB-500MS: Middleware itself adds < 0.01 ms of overhead — negligible.

@app.middleware("http")
async def response_time_middleware(request: Request, call_next):
    """Measure and log the wall-clock time for every request."""
    start = time.perf_counter()

    # call_next hands the request to the actual route handler and waits
    # for the response to come back.
    response = await call_next(request)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"

    logger.info(
        "%s %s → %s (%.2f ms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )

    return response


# =====================================================================
# MODEL LOADING AT STARTUP
# =====================================================================
# WHY load once at startup instead of per-request?
#   joblib.load() reads and deserialises the entire model from disk.
#   For a 200-tree XGBoost ensemble this takes 200-400 ms — far too slow
#   if it happened on every request.  By loading once and storing the model
#   in app.state, subsequent requests just reference the in-memory object
#   (< 0.01 ms pointer lookup), keeping us well under the 500 ms target.
#
# # SUB-500MS: Model and feature order are loaded ONCE and cached in memory.

# @app.on_event("startup") registers a coroutine that FastAPI will call
# exactly once, right after the server boots but before it starts accepting
# HTTP requests.  This is the ideal place for one-time heavy I/O like
# loading ML models or opening database connections.

@app.on_event("startup")
async def load_model():
    """Load the trained XGBoost model and feature column order into memory."""
    model_path = os.path.join(_PROJECT_ROOT, "ml", "model.pkl")
    features_path = os.path.join(_PROJECT_ROOT, "ml", "features.json")

    # --- Load model ------------------------------------------------
    if os.path.isfile(model_path):
        app.state.model = joblib.load(model_path)
        logger.info("Model loaded from %s", model_path)
    else:
        app.state.model = None
        logger.warning(
            "model.pkl not found at %s — /scan will return stub responses. "
            "Run `python ml/train.py` to train the model first.",
            model_path,
        )

    # --- Load feature order ----------------------------------------
    # WARNING: features.json defines the exact column order the model was
    # trained on.  If this file doesn't match the model, predictions will
    # be silently wrong.  Always retrain after changing features.
    if os.path.isfile(features_path):
        with open(features_path, "r") as f:
            data = json.load(f)
        app.state.feature_order = data.get("features", [])
        logger.info(
            "Feature order loaded (%d features): %s",
            len(app.state.feature_order),
            app.state.feature_order,
        )
    else:
        app.state.feature_order = []
        logger.warning(
            "features.json not found at %s — feature alignment disabled.",
            features_path,
        )

    # --- Scan history (in-memory) ----------------------------------
    # WHY in-memory and not a database?
    #   For this project scope, an in-memory list gives us:
    #     • Zero setup — no DB server, no migrations, no connection pool.
    #     • Sub-microsecond appends — just a Python list.append().
    #     • Good enough for a demo that only needs the last 100 scans.
    #   The trade-off is that history is lost on restart.  For production
    #   you'd swap this for SQLite, Redis, or Postgres.
    app.state.scan_history = []


# =====================================================================
# REGISTER ROUTE MODULES
# =====================================================================
# include_router() mounts all the @router.get / @router.post endpoints
# defined in a separate file onto the main app, keeping main.py clean.

app.include_router(health.router)
app.include_router(scan.router)


# =====================================================================
# DEV SERVER
# =====================================================================

if __name__ == "__main__":
    import uvicorn

    # uvicorn.run() starts the ASGI server.
    #   reload=True watches for file changes and auto-restarts — dev only.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
