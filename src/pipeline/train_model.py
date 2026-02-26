import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

IN_PATH = os.path.join("data", "processed", "events.parquet")
MODEL_DIR = "models"

FEATURES = [
    # per-user deviation features (primary signal)
    "z_failures",
    "z_odd_hours",
    "z_mfa_denied",
    "z_vpn_sessions",
    "z_vpn_failures",
    "z_noncompliant",
    "z_bytes_in",
    "z_bytes_out",
    "z_edr_events",
    "z_high_sev",
    "z_unsigned_bins",
    "z_max_speed_kmh",

    # binary/security indicators that should remain absolute
    "impossible_travel",
    "rule_suspicious",
]

def main() -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)
    df = pd.read_parquet(IN_PATH)
    X = df[FEATURES].astype(float)

    model = IsolationForest(n_estimators=300, contamination=0.05, random_state=42)
    model.fit(X)

    out_path = os.path.join(MODEL_DIR, "isoforest.joblib")
    joblib.dump({"model": model, "features": FEATURES}, out_path)
    print(f"Saved model -> {out_path}")

if __name__ == "__main__":
    main()
