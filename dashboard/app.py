import os
import pandas as pd
import streamlit as st

PATH = os.path.join("data", "processed", "scored_events.csv")

st.set_page_config(page_title="Zero Trust AI Dashboard", layout="wide")
st.title("Zero Trust AI — Daily User Risk Dashboard")

if not os.path.exists(PATH):
    st.warning("No scored_events.csv found yet. Run: .\\run.ps1 -Mode gen/build/train/score")
    st.stop()

df = pd.read_csv(PATH)
# =========================
# Case Review Dashboard
# =========================
st.header("Case Review Dashboard")

CASE_PATH = os.path.join("data", "processed", "case_log.csv")

if not os.path.exists(CASE_PATH):
    st.info("No case_log.csv found yet. Use the Spike Day Drill-Down to save a case decision.")
else:
    cases = pd.read_csv(CASE_PATH)

    # Normalize types
    if "timestamp" in cases.columns:
        cases["timestamp"] = pd.to_datetime(cases["timestamp"], errors="coerce")
        cases["date_saved"] = cases["timestamp"].dt.date.astype(str)

    # Basic cleanup
    for col in ["user", "date", "disposition", "notes"]:
        if col in cases.columns:
            cases[col] = cases[col].astype(str)

    # --- Metrics ---
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Cases", int(len(cases)))
    with c2:
        st.metric("Unique Users", int(cases["user"].nunique()) if "user" in cases.columns else 0)
    with c3:
        st.metric("Reviewed (non-Unreviewed)", int((cases.get("disposition", "") != "Unreviewed").sum()) if "disposition" in cases.columns else 0)
    with c4:
        st.metric("Confirmed Compromise", int((cases.get("disposition", "") == "Confirmed Compromise").sum()) if "disposition" in cases.columns else 0)

    # --- Filters ---
    st.subheader("Filters")

    f1, f2, f3 = st.columns([1.2, 1, 1])
    with f1:
        user_opts = ["(all)"] + sorted(cases["user"].unique().tolist()) if "user" in cases.columns else ["(all)"]
        case_user = st.selectbox("User", user_opts, key="case_filter_user")

    with f2:
        disp_opts = ["(all)"] + sorted(cases["disposition"].unique().tolist()) if "disposition" in cases.columns else ["(all)"]
        case_disp = st.selectbox("Disposition", disp_opts, key="case_filter_disp")

    with f3:
        date_opts = ["(all)"] + sorted(cases["date"].unique().tolist()) if "date" in cases.columns else ["(all)"]
        case_date = st.selectbox("Date (event day)", date_opts, key="case_filter_date")

    keyword = st.text_input("Search notes (keyword)", value="", key="case_filter_keyword")

    filtered = cases.copy()
    if case_user != "(all)" and "user" in filtered.columns:
        filtered = filtered[filtered["user"] == case_user]
    if case_disp != "(all)" and "disposition" in filtered.columns:
        filtered = filtered[filtered["disposition"] == case_disp]
    if case_date != "(all)" and "date" in filtered.columns:
        filtered = filtered[filtered["date"].astype(str) == case_date]
    if keyword.strip() and "notes" in filtered.columns:
        filtered = filtered[filtered["notes"].str.contains(keyword.strip(), case=False, na=False)]

    # --- Disposition breakdown ---
    st.subheader("Disposition Breakdown")
    if "disposition" in filtered.columns and len(filtered) > 0:
        disp_counts = filtered["disposition"].value_counts().reset_index()
        disp_counts.columns = ["disposition", "count"]
        st.dataframe(disp_counts, use_container_width=True)
    else:
        st.write("No cases match current filters.")

    # --- Trend: cases over time ---
    st.subheader("Case Volume Trend")
    if "timestamp" in filtered.columns and filtered["timestamp"].notna().any():
        daily = (
            filtered.dropna(subset=["timestamp"])
                    .assign(day=lambda x: x["timestamp"].dt.date.astype(str))
                    .groupby("day")
                    .size()
                    .reset_index(name="cases")
                    .sort_values("day")
        )
        st.line_chart(daily.set_index("day")[["cases"]])
    else:
        st.caption("No valid timestamps found to plot trend.")

    # --- Case table ---
    st.subheader("Case Log (Filtered)")
    show_cols = [c for c in [
        "timestamp","user","date","anomaly_score","anomaly_flag","rule_suspicious","disposition","notes"
    ] if c in filtered.columns]

    st.dataframe(
        filtered.sort_values("timestamp", ascending=False) if "timestamp" in filtered.columns else filtered,
        use_container_width=True
    )

    # --- Download ---
    st.download_button(
        "Download case_log.csv",
        data=cases.to_csv(index=False).encode("utf-8"),
        file_name="case_log.csv",
        mime="text/csv",
        key="download_case_log",
    )

st.divider()

st.sidebar.header("Filters")
user = st.sidebar.selectbox("User", ["(all)"] + sorted(df["user"].unique().tolist()))
dept = st.sidebar.selectbox("Dept", ["(all)"] + sorted(df["dept"].unique().tolist()))
only_flags = st.sidebar.checkbox("Show anomalies only", value=False)

view = df.copy()
if user != "(all)":
    view = view[view["user"] == user]
if dept != "(all)":
    view = view[view["dept"] == dept]
if only_flags:
    view = view[view["anomaly_flag"] == 1]

st.subheader("Top Risk Days")
st.dataframe(
    view.sort_values("anomaly_score", ascending=False)
        [["date","user","dept","anomaly_score","anomaly_flag","rule_suspicious",
          "failures","impossible_travel","mfa_denied","noncompliant","high_sev","unsigned_bins"]]
        .head(30),
    use_container_width=True
)
# --- Drill-down: pick a (user, date) from Top Risk Days and inspect details ---

# --- Drill-down: pick a (user, date) from Top Risk Days and inspect details ---
st.subheader("Spike Day Drill-Down")

drill_candidates = (
    view.sort_values("anomaly_score", ascending=False)
        .head(50)
        .copy()
)

if len(drill_candidates) == 0:
    st.info("No candidates available under current filters.")
else:
    drill_candidates["drill_key"] = (
        drill_candidates["date"].astype(str)
        + " | " + drill_candidates["user"].astype(str)
        + " | score=" + drill_candidates["anomaly_score"].round(3).astype(str)
        + " | flag=" + drill_candidates["anomaly_flag"].astype(int).astype(str)
    )

    chosen = st.selectbox(
        "Select a high-risk day to inspect",
        drill_candidates["drill_key"].tolist(),
        key="drilldown_select",
    )

    sel = drill_candidates[drill_candidates["drill_key"] == chosen].iloc[0]
    sel_user = sel["user"]
    sel_date = str(sel["date"])

    full_row = df[(df["user"] == sel_user) & (df["date"].astype(str) == sel_date)]

    if len(full_row) == 0:
        st.warning("Could not locate the selected row in the full dataset.")
    else:
        r = full_row.iloc[0].to_dict()

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Anomaly Score", float(r.get("anomaly_score", 0)))
        with c2:
            st.metric("Anomaly Flag", int(r.get("anomaly_flag", 0)))
        with c3:
            st.metric("Rule Suspicious", int(r.get("rule_suspicious", 0)))

        st.markdown("**Explanation**")
        st.write(r.get("explanation", "No explanation available."))

        # --- Recommended Analyst Actions ---
        st.markdown("**Recommended Analyst Actions**")

        exp = str(r.get("explanation", "")).lower()
        actions = []

        if "impossible travel" in exp:
            actions.append("Validate user location and recent travel; confirm device/IP ownership.")
        if "mfa" in exp:
            actions.append("Check MFA logs for fatigue patterns and confirm prompts with the user.")
        if "noncompliant" in exp:
            actions.append("Verify endpoint posture and enforce remediation before VPN access.")
        if "high-severity" in exp or float(r.get("high_sev", 0)) >= 1:
            actions.append("Pull EDR process tree and isolate the host if malicious.")
        if float(r.get("z_failures", 0)) >= 3:
            actions.append("Compare today’s auth failures to the user baseline and investigate source IPs.")

        if not actions:
            actions.append("Review telemetry and correlate with recent changes or expected activity.")

        for a in actions[:6]:
            st.write(f"- {a}")

        # --- Key Signals ---
        st.markdown("**Key Signals (raw + baseline deviations)**")

        raw_cols = [
            "failures","odd_hours","mfa_denied",
            "vpn_sessions","vpn_failures","noncompliant",
            "edr_events","high_sev","unsigned_bins",
            "max_speed_kmh","impossible_travel",
        ]

        z_cols = [c for c in [
            "z_failures","z_odd_hours","z_mfa_denied",
            "z_noncompliant","z_high_sev","z_unsigned_bins",
            "z_max_speed_kmh"
        ] if c in df.columns]

        show_cols = (
            ["date","user","dept","anomaly_score","anomaly_flag","rule_suspicious"]
            + [c for c in raw_cols if c in df.columns]
            + z_cols
        )

        detail_df = pd.DataFrame([{k: r.get(k, None) for k in show_cols}])
        st.dataframe(detail_df, use_container_width=True)

        # --- Context window ---
        st.markdown("**User Context (±7 days)**")

        user_all = df[df["user"] == sel_user].copy()
        user_all["date_dt"] = pd.to_datetime(user_all["date"], errors="coerce")
        center = pd.to_datetime(sel_date, errors="coerce")

        if not pd.isna(center):
            window = user_all[
                (user_all["date_dt"] >= center - pd.Timedelta(days=7))
                & (user_all["date_dt"] <= center + pd.Timedelta(days=7))
            ].copy()

            window = window.sort_values("date_dt")
            window["date"] = window["date_dt"].dt.strftime("%Y-%m-%d")

            st.line_chart(window.set_index("date")[["anomaly_score"]])
	    # --- Analyst Disposition Workflow ---
st.markdown("**Analyst Disposition**")

import os
from datetime import datetime

col_a, col_b = st.columns([1, 2])

with col_a:
    disposition = st.selectbox(
        "Verdict",
        ["Unreviewed", "Benign", "Suspicious", "Confirmed Compromise"],
        key="case_disposition",
    )

with col_b:
    notes = st.text_area(
        "Investigation Notes",
        placeholder="Summarize findings, evidence reviewed, and recommended follow-up...",
        key="case_notes",
    )

save_case = st.button("💾 Save Case Decision", key="save_case_btn")

if save_case:
    case_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "user": sel_user,
        "date": sel_date,
        "anomaly_score": float(r.get("anomaly_score", 0)),
        "anomaly_flag": int(r.get("anomaly_flag", 0)),
        "rule_suspicious": int(r.get("rule_suspicious", 0)),
        "disposition": disposition,
        "notes": notes,
    }

    case_path = os.path.join("data", "processed", "case_log.csv")

    import pandas as pd

    if os.path.exists(case_path):
        existing = pd.read_csv(case_path)
        updated = pd.concat([existing, pd.DataFrame([case_record])], ignore_index=True)
    else:
        updated = pd.DataFrame([case_record])

    updated.to_csv(case_path, index=False)

    st.success("Case decision saved to case_log.csv")

            # Show z-score drivers if present
    z_driver_cols = [c for c in ["z_failures","z_mfa_denied","z_noncompliant","z_high_sev","z_max_speed_kmh"] if c in window.columns]
    if z_driver_cols:
                st.caption("Z-score drivers (context window)")
                st.line_chart(window.set_index("date")[z_driver_cols])

    ctx_cols = ["date","anomaly_score","anomaly_flag","rule_suspicious","explanation"] + [c for c in raw_cols if c in window.columns]
    if z_cols:
                ctx_cols += z_driver_cols
    st.dataframe(window[ctx_cols].tail(15), use_container_width=True)

"explanation"

["date","user","dept","anomaly_score","anomaly_flag","rule_suspicious",
 "failures","mfa_denied","noncompliant","high_sev","impossible_travel",
 "z_failures","z_mfa_denied","z_noncompliant","z_high_sev","z_max_speed_kmh",
 "explanation"]

st.subheader("Risk Trend")
st.line_chart(view.sort_values("date").set_index("date")["anomaly_score"])

# --- Top Drivers (per-user deviation view) ---
st.subheader("Top Drivers — Per-User Baseline Deviations")

z_feature_options = [
    "z_failures",
    "z_mfa_denied",
    "z_noncompliant",
    "z_high_sev",
    "z_max_speed_kmh",
]

z_feature = st.selectbox(
    "Select deviation metric (z-score)",
    z_feature_options,
    index=0,
)

top_dev = (
    view.sort_values(z_feature, ascending=False)
        [["date","user","dept", z_feature, "anomaly_score", "anomaly_flag", "explanation"]]
        .head(25)
)

st.dataframe(top_dev, use_container_width=True)

st.caption(
    "Z-scores represent deviation from each user's behavioral baseline. "
    "Values >= 3 typically indicate significant anomalous behavior."
)

# --- Per-user trend "sparkline" (mini time-series panel) ---
st.subheader("Per-User Trend — Sparkline Panel")

# Choose a single user for trend view (default to first user in current filtered view)
available_users = sorted(view["user"].unique().tolist())
trend_user = st.selectbox("Select user for trend view", available_users, key="trend_user_select")

user_df = view[view["user"] == trend_user].copy()
user_df = user_df.sort_values("date")

# Ensure date is treated as string for display (Streamlit line_chart works fine with index)
user_df["date"] = user_df["date"].astype(str)

c1, c2 = st.columns([2, 1])

with c1:
    st.caption("Anomaly score over time (higher = riskier)")
    st.line_chart(user_df.set_index("date")[["anomaly_score"]])

with c2:
    st.caption("Summary (current filter scope)")
    if len(user_df) > 0:
        st.metric("Days in view", int(len(user_df)))
        st.metric("Anomaly days", int((user_df["anomaly_flag"] == 1).sum()))
        st.metric("Rule-suspicious days", int((user_df["rule_suspicious"] == 1).sum()))
    else:
        st.write("No rows for this user under current filters.")

st.caption("Key deviation signals (z-scores) over time")
z_cols = [c for c in ["z_failures","z_mfa_denied","z_noncompliant","z_high_sev","z_max_speed_kmh"] if c in user_df.columns]
if z_cols:
    st.line_chart(user_df.set_index("date")[z_cols])
else:
    st.info("No z-score columns found. Rebuild dataset + retrain to generate z_* features.")
# --- Per-user trend "sparkline" (mini time-series panel) ---
