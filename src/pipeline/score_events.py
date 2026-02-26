import os
import joblib
import pandas as pd

import os
import joblib
import pandas as pd

IN_PATH = os.path.join("data", "processed", "events.parquet")
OUT_PATH = os.path.join("data", "processed", "scored_events.csv")
MODEL_PATH = os.path.join("models", "isoforest.joblib")

def explain_row(r) -> str:
    reasons = []

    # Baseline deviation reasons (z-score based)
    if float(r.get("z_failures", 0)) >= 3:
        reasons.append("Auth failures spike vs user baseline (z>=3)")
    if float(r.get("z_mfa_denied", 0)) >= 3:
        reasons.append("MFA denies spike vs baseline (z>=3)")
    if float(r.get("z_noncompliant", 0)) >= 3:
        reasons.append("Noncompliant posture spike vs baseline (z>=3)")
    if float(r.get("z_high_sev", 0)) >= 3:
        reasons.append("EDR high severity spike vs baseline (z>=3)")
    if float(r.get("z_max_speed_kmh", 0)) >= 3:
        reasons.append("Travel speed spike vs baseline (z>=3)")

    # Rule-based reasons (simple & defensible)
    if int(r.get("impossible_travel", 0)) == 1:
        reasons.append("Impossible travel detected")
    if float(r.get("failures", 0)) >= 8:
        reasons.append("High auth failures")
    if float(r.get("mfa_denied", 0)) >= 2:
        reasons.append("MFA push denies (fatigue)")
    if float(r.get("noncompliant", 0)) >= 1:
        reasons.append("VPN device posture noncompliant")
    if float(r.get("high_sev", 0)) >= 1:
        reasons.append("High-severity EDR event")
    if float(r.get("unsigned_bins", 0)) >= 1:
        reasons.append("Unsigned/suspicious binary observed")
    if float(r.get("odd_hours", 0)) >= 4:
        reasons.append("Excessive odd-hour activity")

    # If the model flags but rules are quiet, still provide a useful explanation
    if not reasons and int(r.get("anomaly_flag", 0)) == 1:
        reasons.append("Behavior deviates from baseline (model anomaly)")

    return "; ".join(reasons) if reasons else "No significant indicators"

def main() -> None:
    df = pd.read_parquet(IN_PATH)
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    features = bundle["features"]

    X = df[features].astype(float)
    normal_score = model.score_samples(X)

    df["anomaly_score"] = -normal_score
    df["anomaly_flag"] = (model.predict(X) == -1).astype(int)

    # Add explainability
    df["explanation"] = df.apply(explain_row, axis=1)

    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote scored output -> {OUT_PATH}")

if __name__ == "__main__":
    main()
