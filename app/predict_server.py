
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from fastapi import FastAPI, Request
from datetime import datetime

app = FastAPI()

MODEL_PATH = Path("../CyberSecurityModel.pkl")
SCALER_PATH = Path("../scaler.pkl")
FEATURE_COLS_PATH = Path("../feature_cols.pkl")
LOG_PATH = Path("live_predictions_log.csv")


LEAKAGE_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_cols = joblib.load(FEATURE_COLS_PATH)


prediction_counts = {}
flow_number = 0
_debug_printed = False


def get_field(d: dict, candidates: list[str]) -> str:
    """Look up a value trying several possible key spellings, since
    cicflowmeter's JSON keys may not match the original CSV column names
    (e.g. 'src_ip' instead of 'Source IP')."""
   
    for c in candidates:
        if c in d:
            return d[c]
    
    lowered = {k.strip().lower().replace(" ", "").replace("_", ""): v for k, v in d.items()}
    for c in candidates:
        key = c.strip().lower().replace(" ", "").replace("_", "")
        if key in lowered:
            return lowered[key]
    return ""


LOG_COLUMNS = ["flow_number", "timestamp", "flow_id", "source_ip", "destination_ip",
               "predicted_label", "confidence"]
if not LOG_PATH.exists():
    pd.DataFrame(columns=LOG_COLUMNS).to_csv(LOG_PATH, index=False)


def preprocess_one_flow(raw: dict) -> pd.DataFrame:
    """Take one flow dict as sent by cicflowmeter, align + scale it exactly
    like training data. Returns a single-row DataFrame ready for model.predict."""
    row = {k.strip(): v for k, v in raw.items()}

    for col in LEAKAGE_COLS:
        row.pop(col, None)

    aligned = {col: row.get(col, 0) for col in feature_cols}
    df = pd.DataFrame([aligned])

    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    df[feature_cols] = scaler.transform(df[feature_cols])
    return df


@app.post("/predict")
async def predict(request: Request):
    global flow_number, _debug_printed
    raw = await request.json()
    raw_stripped = {k.strip(): v for k, v in raw.items()}

    if not _debug_printed:
        print("=== DEBUG: first payload keys received from cicflowmeter ===")
        print(sorted(raw_stripped.keys()))
        print("==============================================================")
        _debug_printed = True

    X = preprocess_one_flow(raw)
    pred = model.predict(X)[0]
    conf = model.predict_proba(X).max()

    flow_number += 1
    prediction_counts[pred] = prediction_counts.get(pred, 0) + 1

    timestamp = datetime.now().isoformat(timespec="seconds")
    flow_id = get_field(raw_stripped, ["Flow ID", "flow_id", "FlowID"])
    source_ip = get_field(raw_stripped, ["Source IP", "src_ip", "srcip", "Src IP"])
    destination_ip = get_field(raw_stripped, ["Destination IP", "dst_ip", "dstip", "Dst IP"])

  
    flag = "⚠️ " if pred != "BENIGN" else "   "
    print(f"{flag}[{flow_number}] {timestamp} {source_ip} -> {destination_ip} → {pred} (confidence: {conf:.2f})")

    
    if flow_number % 100 == 0:
        print(f"--- Summary after {flow_number} flows: {prediction_counts} ---")

    
    pd.DataFrame([{
        "flow_number": flow_number,
        "timestamp": timestamp,
        "flow_id": flow_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "predicted_label": pred,
        "confidence": conf
    }]).to_csv(LOG_PATH, mode="a", header=False, index=False)

    return {"predicted_label": str(pred), "confidence": float(conf)}


@app.get("/summary")
async def summary():
    return {"total_flows": flow_number, "counts": prediction_counts}