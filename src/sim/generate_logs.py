import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

US_CITIES = [
    ("Fort Worth", "TX", 32.7555, -97.3308),
    ("Dallas", "TX", 32.7767, -96.7970),
    ("Austin", "TX", 30.2672, -97.7431),
    ("San Antonio", "TX", 29.4241, -98.4936),
    ("Denver", "CO", 39.7392, -104.9903),
    ("Seattle", "WA", 47.6062, -122.3321),
    ("New York", "NY", 40.7128, -74.0060),
    ("Miami", "FL", 25.7617, -80.1918),
    ("Los Angeles", "CA", 34.0522, -118.2437),
    ("London", "UK", 51.5072, -0.1276),
    ("Tokyo", "JP", 35.6762, 139.6503),
]

USERS = [
    ("rholmes", "analyst", "Engineering"),
    ("jdoe", "engineer", "Engineering"),
    ("asmith", "admin", "IT"),
    ("svc_backup", "service", "IT"),
    ("svc_ci", "service", "Engineering"),
    ("mbrown", "manager", "Programs"),
    ("knguyen", "engineer", "Security"),
]

HOSTS = ["LAP-1042", "LAP-2201", "WS-7781", "WS-1140", "SRV-AD01", "SRV-SIEM01", "SRV-FS02"]
APPS = ["m365", "vpn", "jira", "confluence", "git", "azure_portal", "okta"]
EDR_ACTIONS = ["ALLOW", "BLOCK", "QUARANTINE"]

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def rand_ts(start: datetime, end: datetime) -> datetime:
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def choose_city(anomalous: bool) -> tuple:
    if not anomalous:
        roll = random.random()
        if roll < 0.75:
            return random.choice([c for c in US_CITIES if c[1] == "TX"])
        return random.choice([c for c in US_CITIES if c[1] in {"CO","WA","NY","FL","CA"}])
    return random.choice([c for c in US_CITIES if c[1] in {"UK","JP"}])

def write_jsonl(path: str, events: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

def main(rows: int) -> None:
    random.seed(42)

    out_dir = os.path.join("data", "raw")
    ensure_dir(out_dir)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=60)

    auth_events = []
    vpn_events = []
    edr_events = []

    for _ in range(rows):
        user, utype, dept = random.choice(USERS)
        host = random.choice(HOSTS)
        app = random.choice(APPS)

        is_anom = random.random() < 0.03
        ts = rand_ts(start, end)

        city, region, lat, lon = choose_city(is_anom)

        result = "SUCCESS" if random.random() < 0.92 else "FAILURE"
        if is_anom and random.random() < 0.6:
            result = "FAILURE" if random.random() < 0.7 else "SUCCESS"

        mfa = True if utype != "service" else False
        if is_anom and utype != "service":
            mfa_result = "PUSH_DENIED" if random.random() < 0.5 else "PUSH_ACCEPTED"
        else:
            mfa_result = "PUSH_ACCEPTED" if mfa else "N/A"

        auth_events.append({
            "source": "auth",
            "ts": ts.isoformat(),
            "user": user,
            "user_type": utype,
            "dept": dept,
            "host": host,
            "app": app,
            "ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                  if not is_anom else
                  f"{random.randint(20,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "geo_city": city,
            "geo_region": region,
            "geo_lat": lat,
            "geo_lon": lon,
            "result": result,
            "mfa": mfa,
            "mfa_result": mfa_result,
        })

        if app == "vpn" or random.random() < 0.25:
            vpn_events.append({
                "source": "vpn",
                "ts": ts.isoformat(),
                "user": user,
                "host": host,
                "tunnel": random.choice(["IPSEC", "SSL"]),
                "device_posture": random.choice(["COMPLIANT", "NONCOMPLIANT"]) if is_anom else random.choice(["COMPLIANT"]*9 + ["NONCOMPLIANT"]),
                "bytes_in": random.randint(10_000, 10_000_000),
                "bytes_out": random.randint(10_000, 10_000_000),
                "geo_city": city,
                "geo_region": region,
                "result": "CONNECTED" if random.random() < 0.97 else "FAILED",
            })

        if random.random() < 0.35:
            suspicious_proc = is_anom and random.random() < 0.5
            proc = random.choice(["powershell.exe", "cmd.exe", "chrome.exe", "msedge.exe", "outlook.exe", "svchost.exe"])
            if suspicious_proc:
                proc = random.choice(["powershell.exe", "rundll32.exe", "wmic.exe"])

            edr_events.append({
                "source": "edr",
                "ts": ts.isoformat(),
                "user": user,
                "host": host,
                "process": proc,
                "severity": random.choice(["LOW","MEDIUM","HIGH"]) if suspicious_proc else random.choice(["LOW"]*8 + ["MEDIUM"]*2),
                "action": random.choice(EDR_ACTIONS),
                "signed_binary": False if suspicious_proc else (random.random() < 0.95),
            })

    write_jsonl(os.path.join(out_dir, "auth.jsonl"), auth_events)
    write_jsonl(os.path.join(out_dir, "vpn.jsonl"), vpn_events)
    write_jsonl(os.path.join(out_dir, "edr.jsonl"), edr_events)

    print(f"Generated: {len(auth_events)} auth, {len(vpn_events)} vpn, {len(edr_events)} edr events -> data/raw/*.jsonl")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=50000)
    args = ap.parse_args()
    main(args.rows)
