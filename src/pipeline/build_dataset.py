import json
import os
from dateutil import parser as dtparser

import numpy as np
import pandas as pd

RAW_DIR = os.path.join("data", "raw")
OUT_DIR = os.path.join("data", "processed")

def read_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows

def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
    return 2 * r * np.arcsin(np.sqrt(a))

def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    auth = pd.DataFrame(read_jsonl(os.path.join(RAW_DIR, "auth.jsonl")))
    vpn  = pd.DataFrame(read_jsonl(os.path.join(RAW_DIR, "vpn.jsonl")))
    edr  = pd.DataFrame(read_jsonl(os.path.join(RAW_DIR, "edr.jsonl")))

    for df in (auth, vpn, edr):
        df["ts"] = df["ts"].apply(dtparser.isoparse)
        df["date"] = df["ts"].dt.date
        df["hour"] = df["ts"].dt.hour

    auth = auth.sort_values(["user", "ts"]).reset_index(drop=True)
    auth["prev_ts"] = auth.groupby("user")["ts"].shift(1)
    auth["prev_lat"] = auth.groupby("user")["geo_lat"].shift(1)
    auth["prev_lon"] = auth.groupby("user")["geo_lon"].shift(1)

    auth["dist_km"] = haversine_km(
        auth["prev_lat"].fillna(auth["geo_lat"]),
        auth["prev_lon"].fillna(auth["geo_lon"]),
        auth["geo_lat"],
        auth["geo_lon"],
    )
    auth["delta_hours"] = (auth["ts"] - auth["prev_ts"]).dt.total_seconds() / 3600.0
    auth["delta_hours"] = auth["delta_hours"].replace([np.inf, -np.inf], np.nan).fillna(9999)
    auth["speed_kmh"] = auth["dist_km"] / auth["delta_hours"].clip(lower=0.25)
    auth["impossible_travel"] = (auth["speed_kmh"] > 900).astype(int)

    auth["is_failure"] = (auth["result"] == "FAILURE").astype(int)
    auth["odd_hour"] = ((auth["hour"] < 6) | (auth["hour"] > 20)).astype(int)
    auth["mfa_denied"] = (auth["mfa_result"] == "PUSH_DENIED").astype(int)

    daily = auth.groupby(["user", "date"]).agg(
        auth_events=("result", "count"),
        failures=("is_failure", "sum"),
        odd_hours=("odd_hour", "sum"),
        impossible_travel=("impossible_travel", "max"),
        mfa_denied=("mfa_denied", "sum"),
        max_speed_kmh=("speed_kmh", "max"),
        dept=("dept", "last"),
    ).reset_index()

    vpn["noncompliant"] = (vpn["device_posture"] == "NONCOMPLIANT").astype(int)
    vpn_daily = vpn.groupby(["user", "date"]).agg(
        vpn_sessions=("result", "count"),
        vpn_failures=("result", lambda x: int((x == "FAILED").sum())),
        noncompliant=("noncompliant", "sum"),
        bytes_in=("bytes_in", "sum"),
        bytes_out=("bytes_out", "sum"),
    ).reset_index()

    edr["high"] = (edr["severity"] == "HIGH").astype(int)
    edr["unsigned"] = (~edr["signed_binary"]).astype(int)
    edr_daily = edr.groupby(["user", "date"]).agg(
        edr_events=("severity", "count"),
        high_sev=("high", "sum"),
        unsigned_bins=("unsigned", "sum"),
    ).reset_index()

    df = daily.merge(vpn_daily, on=["user","date"], how="left").merge(edr_daily, on=["user","date"], how="left")
    df = df.fillna(0)

    df["rule_suspicious"] = (
        (df["impossible_travel"] == 1)
        | (df["failures"] >= 8)
        | (df["noncompliant"] >= 1)
        | (df["high_sev"] >= 1)
        | (df["mfa_denied"] >= 2)
    ).astype(int)

    # --- Per-user baselines (z-scores) ---
    # Compute mean/std per user across the dataset, then score each day relative to that user's baseline.
    z_cols = [
        "failures",
        "odd_hours",
        "mfa_denied",
        "vpn_sessions",
        "vpn_failures",
        "noncompliant",
        "bytes_in",
        "bytes_out",
        "edr_events",
        "high_sev",
        "unsigned_bins",
        "max_speed_kmh",
    ]

    # Ensure numeric
    for c in z_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    stats = df.groupby("user")[z_cols].agg(["mean", "std"])
    stats.columns = [f"{col}_{agg}" for col, agg in stats.columns]
    df = df.merge(stats.reset_index(), on="user", how="left")

    # Z = (x - mean) / std ; protect against std=0
    eps = 1e-6
    for c in z_cols:
        mu = df[f"{c}_mean"]
        sd = df[f"{c}_std"].replace(0, eps).fillna(eps)
        df[f"z_{c}"] = (df[c] - mu) / sd

    # Optional: cap extreme z-scores for stability
    for c in z_cols:
        df[f"z_{c}"] = df[f"z_{c}"].clip(lower=-8, upper=8)

    df.to_parquet(os.path.join(OUT_DIR, "events.parquet"), index=False)
    df.to_csv(os.path.join(OUT_DIR, "events.csv"), index=False)

    print(f"Wrote dataset -> data/processed/events.parquet (rows={len(df)})")

if __name__ == "__main__":
    main()
