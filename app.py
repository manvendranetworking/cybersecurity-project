"""
CyberShield — Security Monitoring & Threat Detection Dashboard
==============================================================
All data shown is SIMULATED for demonstration and learning purposes only.
This application is NOT connected to any real network, system, or database.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

# ── Page configuration ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield · Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & COLOUR PALETTE
# ══════════════════════════════════════════════════════════════════════════════
# All colours are defined once here so they stay consistent throughout the file.
CLR_BG        = "#0b0f19"   # page background — deep midnight navy
CLR_SURFACE   = "#131929"   # card / panel surface
CLR_BORDER    = "#1e2d45"   # subtle border
CLR_TEXT      = "#cdd9e5"   # primary text
CLR_MUTED     = "#637083"   # secondary / caption text
CLR_ACCENT    = "#3b82f6"   # electric blue — primary accent
CLR_SUCCESS   = "#22c55e"   # muted green
CLR_WARNING   = "#f59e0b"   # amber
CLR_DANGER    = "#ef4444"   # controlled red
CLR_HIGH_BG   = "#1f1010"
CLR_MED_BG    = "#1f1a0a"
CLR_LOW_BG    = "#0c1f13"

# Detection rule threshold — configurable in one place
SUSPICIOUS_THRESHOLD = 5

# ══════════════════════════════════════════════════════════════════════════════
# SIMULATED LOGIN RECORDS
# ══════════════════════════════════════════════════════════════════════════════
# These 10 records are entirely fictional and created for learning purposes.
# IP 192.168.1.77 has 5 consecutive failed attempts, demonstrating a
# classic brute-force pattern for educational purposes.
SAMPLE_RECORDS = [
    {"Time": "2024-06-10 08:02:14", "Username": "alice",  "IP Address": "10.0.0.5",      "Result": "Success"},
    {"Time": "2024-06-10 08:15:33", "Username": "bob",    "IP Address": "10.0.0.12",     "Result": "Success"},
    {"Time": "2024-06-10 08:31:07", "Username": "admin",  "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:31:45", "Username": "admin",  "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:32:09", "Username": "admin",  "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:32:51", "Username": "admin",  "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:33:14", "Username": "admin",  "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2024-06-10 09:05:22", "Username": "carol",  "IP Address": "10.0.0.8",      "Result": "Success"},
    {"Time": "2024-06-10 09:45:58", "Username": "eve",    "IP Address": "10.0.0.34",     "Result": "Success"},
    {"Time": "2024-06-10 10:00:03", "Username": "frank",  "IP Address": "10.0.0.7",      "Result": "Success"},
]

# Illustrative aggregate metrics — these represent a larger historical dataset,
# NOT the 10 sample records above. Clearly separated to avoid confusion.
AGG_TOTAL     = 1_284
AGG_SUCCESS   = 973
AGG_FAILED    = 248
AGG_SUSP_BASE = 63   # baseline suspicious count before sample-record analysis


# ══════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def count_failures_per_ip(records):
    """Return a dict mapping each IP to its total failed-login count."""
    counts = {}
    for r in records:
        if r["Result"] == "Failed":
            ip = r["IP Address"]
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def get_risk_level(fail_count):
    """
    Classify an IP's risk level based on failed-login count.
    Thresholds: High ≥ 10, Medium ≥ 5, Low < 5.
    These are simple educational rules, not production standards.
    """
    if fail_count >= 10:
        return "High"
    elif fail_count >= SUSPICIOUS_THRESHOLD:
        return "Medium"
    else:
        return "Low"


def get_first_last_time(records, ip):
    """Return the first and last timestamps for Failed attempts from a given IP."""
    times = [
        r["Time"] for r in records
        if r["IP Address"] == ip and r["Result"] == "Failed"
    ]
    if not times:
        return "—", "—"
    return min(times), max(times)


def build_alerts(records, threshold):
    """
    Run the detection rule against records and return a list of alert dicts,
    sorted by risk (High first) then by fail count (descending).
    """
    failed_counts = count_failures_per_ip(records)
    alerts = []

    for ip, fail_count in failed_counts.items():
        if fail_count < threshold:
            continue

        # Collect the target username (last failed attempt username for this IP)
        username = "unknown"
        for r in records:
            if r["IP Address"] == ip and r["Result"] == "Failed":
                username = r["Username"]

        first_time, last_time = get_first_last_time(records, ip)
        risk = get_risk_level(fail_count)

        alerts.append({
            "ip":          ip,
            "username":    username,
            "fail_count":  fail_count,
            "risk":        risk,
            "first_time":  first_time,
            "last_time":   last_time,
            "reason": (
                f"{fail_count} failed login attempts targeting account "
                f"'{username}' from a single IP address. "
                f"Attempts spanned {first_time} to {last_time}. "
                f"Flagged because {fail_count} ≥ threshold of {threshold}."
            ),
            "investigation": (
                "1. Verify whether this IP belongs to a known employee or system. "
                "2. Check whether the account was eventually accessed successfully. "
                "3. Review other activity from this IP in broader system logs. "
                "4. Consider temporarily blocking this IP if the pattern continues."
            ),
        })

    # Sort: High first, then Medium, then Low; within each level sort by fail count desc
    risk_order = {"High": 0, "Medium": 1, "Low": 2}
    alerts.sort(key=lambda a: (risk_order[a["risk"]], -a["fail_count"]))
    return alerts, failed_counts


# ══════════════════════════════════════════════════════════════════════════════
# CSS — Professional SOC dark theme
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
/* ── Global ──────────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"], .stApp {{
    background-color: {CLR_BG};
    color: {CLR_TEXT};
    font-family: "Inter", "Segoe UI", system-ui, sans-serif;
}}
[data-testid="stSidebar"] {{
    background-color: {CLR_SURFACE};
    border-right: 1px solid {CLR_BORDER};
}}
[data-testid="stSidebar"] * {{ color: {CLR_TEXT}; }}

/* ── Header strip ────────────────────────────────────────────── */
.cs-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 0 10px 0;
    border-bottom: 1px solid {CLR_BORDER};
    margin-bottom: 6px;
}}
.cs-logo {{
    font-size: 2.2rem;
    line-height: 1;
}}
.cs-title {{
    font-size: 1.55rem;
    font-weight: 700;
    color: {CLR_ACCENT};
    margin: 0;
    letter-spacing: -0.02em;
}}
.cs-subtitle {{
    font-size: 0.8rem;
    color: {CLR_MUTED};
    margin: 2px 0 0 0;
}}
.cs-badge-demo {{
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    background: #1a2540;
    color: {CLR_ACCENT};
    border: 1px solid {CLR_ACCENT};
    border-radius: 4px;
    padding: 2px 8px;
    margin-left: auto;
    white-space: nowrap;
    align-self: flex-start;
    margin-top: 6px;
}}

/* ── Status bar ──────────────────────────────────────────────── */
.cs-statusbar {{
    display: flex;
    gap: 20px;
    align-items: center;
    font-size: 0.75rem;
    color: {CLR_MUTED};
    padding: 6px 0 14px 0;
    border-bottom: 1px solid {CLR_BORDER};
    margin-bottom: 20px;
}}
.cs-statusbar .dot {{
    width: 7px; height: 7px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 5px;
    background: {CLR_SUCCESS};
}}

/* ── Metric cards ────────────────────────────────────────────── */
.cs-card {{
    background: {CLR_SURFACE};
    border: 1px solid {CLR_BORDER};
    border-radius: 10px;
    padding: 18px 16px 14px;
    position: relative;
    overflow: hidden;
}}
.cs-card-accent {{
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 10px 10px 0 0;
}}
.cs-card-icon {{ font-size: 1.15rem; margin-bottom: 6px; opacity: 0.85; }}
.cs-card-value {{
    font-size: 2rem;
    font-weight: 700;
    margin: 0;
    line-height: 1.15;
}}
.cs-card-label {{
    font-size: 0.78rem;
    color: {CLR_MUTED};
    margin: 4px 0 0 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
.cs-card-sub {{
    font-size: 0.73rem;
    color: {CLR_MUTED};
    margin-top: 6px;
    padding-top: 6px;
    border-top: 1px solid {CLR_BORDER};
}}

/* ── Section headings ────────────────────────────────────────── */
.cs-section-title {{
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: {CLR_MUTED};
    margin: 0 0 14px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid {CLR_BORDER};
}}

/* ── Alert cards ─────────────────────────────────────────────── */
.cs-alert {{
    border-radius: 8px;
    border: 1px solid {CLR_BORDER};
    padding: 14px 16px;
    margin-bottom: 10px;
    position: relative;
}}
.cs-alert-high   {{ background:{CLR_HIGH_BG}; border-left:3px solid {CLR_DANGER};  }}
.cs-alert-medium {{ background:{CLR_MED_BG};  border-left:3px solid {CLR_WARNING}; }}
.cs-alert-low    {{ background:{CLR_LOW_BG};  border-left:3px solid {CLR_SUCCESS}; }}

.cs-alert-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
}}
.cs-alert-title {{ font-size: 0.9rem; font-weight: 600; margin: 0; }}

.cs-badge {{
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.07em;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
}}
.cs-badge-high   {{ background:{CLR_HIGH_BG}; color:{CLR_DANGER};  border:1px solid {CLR_DANGER};  }}
.cs-badge-medium {{ background:{CLR_MED_BG};  color:{CLR_WARNING}; border:1px solid {CLR_WARNING}; }}
.cs-badge-low    {{ background:{CLR_LOW_BG};  color:{CLR_SUCCESS}; border:1px solid {CLR_SUCCESS}; }}

.cs-alert-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 6px 20px;
    font-size: 0.8rem;
}}
.cs-alert-kv {{ margin: 0; }}
.cs-alert-kv .k {{ color: {CLR_MUTED}; }}
.cs-alert-kv .v {{ color: {CLR_TEXT};  font-weight: 500; }}

.cs-alert-note {{
    font-size: 0.75rem;
    color: {CLR_MUTED};
    background: rgba(255,255,255,0.03);
    border: 1px solid {CLR_BORDER};
    border-radius: 5px;
    padding: 7px 10px;
    margin-top: 10px;
}}

/* ── Misc ────────────────────────────────────────────────────── */
.cs-disclaimer {{
    font-size: 0.75rem;
    color: {CLR_MUTED};
    background: rgba(59,130,246,0.06);
    border: 1px solid rgba(59,130,246,0.2);
    border-radius: 6px;
    padding: 8px 12px;
    margin-bottom: 14px;
}}
.cs-empty {{
    text-align: center;
    padding: 28px;
    color: {CLR_MUTED};
    font-size: 0.85rem;
    background: {CLR_SURFACE};
    border: 1px dashed {CLR_BORDER};
    border-radius: 8px;
}}
.cs-footer {{
    font-size: 0.72rem;
    color: {CLR_MUTED};
    text-align: center;
    padding: 16px 0 8px;
    border-top: 1px solid {CLR_BORDER};
    margin-top: 20px;
}}

/* ── Hide default Streamlit chrome ───────────────────────────── */
#MainMenu, footer, [data-testid="stToolbar"] {{ visibility: hidden; }}

/* ── Streamlit widget label colour ───────────────────────────── */
label, .stSelectbox label, .stTextInput label {{ color: {CLR_MUTED} !important; font-size:0.78rem !important; }}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: render a metric card
# ══════════════════════════════════════════════════════════════════════════════
def metric_card(icon, value, label, accent_colour, sub_text=""):
    """Render a single metric card using the cs-card CSS classes."""
    sub_html = (
        f'<p class="cs-card-sub">{sub_text}</p>' if sub_text else ""
    )
    st.markdown(f"""
    <div class="cs-card">
        <div class="cs-card-accent" style="background:{accent_colour};"></div>
        <div class="cs-card-icon">{icon}</div>
        <p class="cs-card-value" style="color:{accent_colour};">{value}</p>
        <p class="cs-card-label">{label}</p>
        {sub_html}
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PLOTLY THEME DEFAULTS  (applied to every figure)
# ══════════════════════════════════════════════════════════════════════════════
PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter,Segoe UI,system-ui,sans-serif", color=CLR_MUTED, size=12),
    margin=dict(l=10, r=10, t=36, b=10),
    showlegend=True,
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        font=dict(color=CLR_TEXT, size=11),
        orientation="h",
        yanchor="bottom", y=1.02,
        xanchor="right",  x=1,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# DATA PREPARATION  (runs once per session reload)
# ══════════════════════════════════════════════════════════════════════════════
df_all = pd.DataFrame(SAMPLE_RECORDS)
df_all["Time"] = pd.to_datetime(df_all["Time"])   # parse timestamps

# Run detection engine
ALERTS, failed_counts = build_alerts(SAMPLE_RECORDS, SUSPICIOUS_THRESHOLD)
suspicious_ips = [a["ip"] for a in ALERTS]
suspicious_acts = AGG_SUSP_BASE + len(suspicious_ips)

# Derived stats from the 10 sample records (clearly labelled as such)
sample_total   = len(df_all)
sample_success = len(df_all[df_all["Result"] == "Success"])
sample_failed  = len(df_all[df_all["Result"] == "Failed"])
sample_susp    = len(suspicious_ips)

# Rates from the illustrative aggregate dataset
agg_success_pct = round(AGG_SUCCESS / AGG_TOTAL * 100, 1)
agg_failed_pct  = round(AGG_FAILED  / AGG_TOTAL * 100, 1)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — Navigation & global controls
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(f"""
    <div style="text-align:center;padding:10px 0 18px;">
        <span style="font-size:2.4rem;">🛡️</span>
        <p style="font-size:1.1rem;font-weight:700;color:{CLR_ACCENT};margin:4px 0 0;">CyberShield</p>
        <p style="font-size:0.7rem;color:{CLR_MUTED};margin:0;">Security Monitoring</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Section navigation
    section = st.radio(
        "Navigate",
        options=["Overview", "Login Activity", "Visual Analytics", "Security Alerts"],
        label_visibility="collapsed",
    )

    st.markdown("---")

    # Configurable detection threshold
    threshold_input = st.number_input(
        "Detection threshold (min failed logins to flag an IP)",
        min_value=2,
        max_value=20,
        value=SUSPICIOUS_THRESHOLD,
        step=1,
        help="An IP address is flagged as suspicious when its failed-login count reaches this number.",
    )

    # Reload data button — resets session state
    if st.button("↺  Reload Data", use_container_width=True):
        st.session_state.pop("show_table", None)
        st.rerun()

    st.markdown("---")
    st.markdown(f"""
    <p style="font-size:0.7rem;color:{CLR_MUTED};text-align:center;">
        All data is simulated.<br>No real network connection.
    </p>
    """, unsafe_allow_html=True)


# Re-run detection with the sidebar threshold (in case user changed it)
if threshold_input != SUSPICIOUS_THRESHOLD:
    ALERTS, failed_counts = build_alerts(SAMPLE_RECORDS, threshold_input)
    suspicious_ips  = [a["ip"] for a in ALERTS]
    suspicious_acts = AGG_SUSP_BASE + len(suspicious_ips)

effective_threshold = threshold_input


# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
now_str = datetime.now().strftime("%d %b %Y  %H:%M")

st.markdown(f"""
<div class="cs-header">
    <span class="cs-logo">🛡️</span>
    <div>
        <p class="cs-title">CyberShield</p>
        <p class="cs-subtitle">Security Monitoring &amp; Threat Detection</p>
    </div>
    <span class="cs-badge-demo">SIMULATED DATA · DEMO ENVIRONMENT</span>
</div>
<div class="cs-statusbar">
    <span><span class="dot"></span>System Online</span>
    <span>·</span>
    <span>Last refreshed: {now_str}</span>
    <span>·</span>
    <span>10 sample records loaded</span>
    <span>·</span>
    <span>Detection threshold: ≥ {effective_threshold} failures</span>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION A — OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if section == "Overview":

    st.markdown('<p class="cs-section-title">Executive Overview — Illustrative Aggregate Metrics</p>', unsafe_allow_html=True)
    st.caption(
        "The four cards below reflect a larger illustrative dataset (1,284 events). "
        "The 10 sample records in Login Activity are a separate, detailed subset used "
        "for demonstration and rule-based detection."
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card(
            "🔐", f"{AGG_TOTAL:,}", "Total Logins", CLR_ACCENT,
            sub_text="Illustrative aggregate dataset",
        )
    with c2:
        metric_card(
            "✓", f"{AGG_SUCCESS:,}", "Successful Logins", CLR_SUCCESS,
            sub_text=f"{agg_success_pct}% success rate",
        )
    with c3:
        metric_card(
            "✗", f"{AGG_FAILED:,}", "Failed Logins", CLR_DANGER,
            sub_text=f"{agg_failed_pct}% failure rate",
        )
    with c4:
        metric_card(
            "⚠", f"{suspicious_acts:,}", "Suspicious Activities", CLR_WARNING,
            sub_text=f"Includes {len(suspicious_ips)} IP(s) flagged in sample",
        )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="cs-section-title">Sample Records Snapshot (10 records)</p>', unsafe_allow_html=True)
    st.caption("Statistics calculated directly from the 10 simulated login records below.")

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        metric_card("📋", str(sample_total),   "Total Sample Records", CLR_ACCENT)
    with s2:
        metric_card("✓",  str(sample_success), "Successful",           CLR_SUCCESS)
    with s3:
        metric_card("✗",  str(sample_failed),  "Failed",               CLR_DANGER)
    with s4:
        metric_card("⚠",  str(sample_susp),    "Flagged IPs",          CLR_WARNING)

    # Quick IP suspect summary
    if ALERTS:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p class="cs-section-title">Top Suspicious IP Addresses</p>', unsafe_allow_html=True)
        summary_rows = [
            {
                "IP Address":      a["ip"],
                "Target Username": a["username"],
                "Failed Attempts": a["fail_count"],
                "Risk Level":      a["risk"],
                "First Attempt":   a["first_time"],
                "Last Attempt":    a["last_time"],
            }
            for a in ALERTS
        ]
        st.dataframe(
            pd.DataFrame(summary_rows),
            use_container_width=True,
            hide_index=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION B — LOGIN ACTIVITY
# ══════════════════════════════════════════════════════════════════════════════
elif section == "Login Activity":

    st.markdown('<p class="cs-section-title">Login Activity — 10 Simulated Records</p>', unsafe_allow_html=True)

    # ── Filters ───────────────────────────────────────────────────────────────
    # Keys used by every filter widget — stored here so we can delete them all
    # from st.session_state when the user clicks "Clear Filters".
    FILTER_KEYS = ["filter_result", "filter_user", "filter_ip", "filter_search"]

    with st.expander("Filters & Search", expanded=True):
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            result_filter = st.selectbox(
                "Login Result",
                ["All", "Success", "Failed"],
                key="filter_result",
                help="Filter rows by whether the login attempt succeeded or failed.",
            )
        with fc2:
            all_users = ["All"] + sorted(df_all["Username"].unique().tolist())
            user_filter = st.selectbox(
                "Username",
                all_users,
                key="filter_user",
                help="Show only records for a specific username.",
            )
        with fc3:
            all_ips = ["All"] + sorted(df_all["IP Address"].unique().tolist())
            ip_filter = st.selectbox(
                "IP Address",
                all_ips,
                key="filter_ip",
                help="Show only records from a specific IP address.",
            )

        col_search, col_reset = st.columns([3, 1])
        with col_search:
            search_text = st.text_input(
                "Search (username or IP address)",
                placeholder="e.g. admin  or  192.168",
                key="filter_search",
                label_visibility="visible",
            )
        with col_reset:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Clear Filters", use_container_width=True):
                # Delete every filter key from session_state before rerunning.
                # This forces Streamlit to render each widget at its default value.
                for k in FILTER_KEYS:
                    st.session_state.pop(k, None)
                st.rerun()

    # ── Apply filters ─────────────────────────────────────────────────────────
    df_view = df_all.copy()

    if result_filter != "All":
        df_view = df_view[df_view["Result"] == result_filter]
    if user_filter != "All":
        df_view = df_view[df_view["Username"] == user_filter]
    if ip_filter != "All":
        df_view = df_view[df_view["IP Address"] == ip_filter]
    if search_text.strip():
        mask = (
            df_view["Username"].str.contains(search_text.strip(), case=False, na=False) |
            df_view["IP Address"].str.contains(search_text.strip(), case=False, na=False)
        )
        df_view = df_view[mask]

    # ── Load/show data ────────────────────────────────────────────────────────
    if "show_table" not in st.session_state:
        st.session_state.show_table = False

    if st.button("Load / Refresh Sample Data", type="primary"):
        st.session_state.show_table = True

    if st.session_state.show_table:
        if df_view.empty:
            st.markdown(
                '<div class="cs-empty">No records match the current filters. '
                'Try adjusting your search or click <b>Clear Filters</b>.</div>',
                unsafe_allow_html=True,
            )
        else:
            # Flag suspicious IPs with a visual marker in the table
            display_df = df_view.copy()
            display_df["Time"] = display_df["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
            display_df["Flagged"] = display_df["IP Address"].apply(
                lambda ip: "⚠ Suspicious" if ip in suspicious_ips else ""
            )

            # Style: colour the Result and Flagged columns
            def style_row(val):
                if val == "Success":
                    return f"color:{CLR_SUCCESS}; font-weight:600;"
                elif val == "Failed":
                    return f"color:{CLR_DANGER}; font-weight:600;"
                elif val == "⚠ Suspicious":
                    return f"color:{CLR_WARNING}; font-weight:600;"
                return ""

            styled = display_df.style.map(style_row, subset=["Result", "Flagged"])
            st.dataframe(styled, use_container_width=True, hide_index=True)

            # Row count summary
            shown   = len(df_view)
            succ_n  = len(df_view[df_view["Result"] == "Success"])
            fail_n  = len(df_view[df_view["Result"] == "Failed"])
            flagged = len(df_view[df_view["IP Address"].isin(suspicious_ips)])
            st.caption(
                f"Showing {shown} of {sample_total} records — "
                f"✓ {succ_n} successful · ✗ {fail_n} failed · ⚠ {flagged} from flagged IPs"
            )

            # ── CSV download ──────────────────────────────────────────────────
            csv_data = display_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download as CSV",
                data=csv_data,
                file_name="cybershield_login_records.csv",
                mime="text/csv",
                help="Download the currently displayed (filtered) records as a CSV file.",
            )

        # IP flags legend
        if suspicious_ips:
            st.caption(
                f"⚠ Flagged IPs: {', '.join(suspicious_ips)}  "
                f"(≥ {effective_threshold} failed attempts from the same address)"
            )
    else:
        st.markdown(
            '<div class="cs-empty">Click <b>Load / Refresh Sample Data</b> to display the records.</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION C — VISUAL ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
elif section == "Visual Analytics":

    st.markdown('<p class="cs-section-title">Visual Analytics — Based on 10 Simulated Records</p>', unsafe_allow_html=True)

    # ── Chart 1: Login outcome comparison ─────────────────────────────────────
    st.markdown("**1 · Login Outcome Comparison**")
    st.caption(
        "Compares successful vs failed login attempts across the 10 sample records. "
        "A high failure count relative to successes warrants investigation."
    )

    fig1 = go.Figure()
    fig1.add_trace(go.Bar(
        name="Successful",
        x=["Login Outcomes"],
        y=[sample_success],
        marker_color=CLR_SUCCESS,
        text=[sample_success],
        textposition="outside",
        textfont=dict(color=CLR_TEXT),
        width=0.3,
    ))
    fig1.add_trace(go.Bar(
        name="Failed",
        x=["Login Outcomes"],
        y=[sample_failed],
        marker_color=CLR_DANGER,
        text=[sample_failed],
        textposition="outside",
        textfont=dict(color=CLR_TEXT),
        width=0.3,
    ))
    fig1.update_layout(
        **PLOT_LAYOUT,
        title=dict(text="Successful vs Failed Logins (sample)", font=dict(color=CLR_TEXT, size=13)),
        yaxis=dict(
            gridcolor=CLR_BORDER,
            title="Number of Attempts",
            title_font=dict(color=CLR_MUTED),
        ),
        xaxis=dict(showticklabels=False),
        barmode="group",
        height=300,
    )
    st.plotly_chart(fig1, use_container_width=True)

    st.markdown("---")

    # ── Chart 2: Failed logins by IP ──────────────────────────────────────────
    st.markdown("**2 · Failed Login Attempts by IP Address**")
    st.caption(
        "Each bar shows how many times a given IP address produced a failed login. "
        "Addresses at or above the detection threshold are highlighted in amber."
    )

    df_failed_ips = (
        df_all[df_all["Result"] == "Failed"]
        .groupby("IP Address")
        .size()
        .reset_index(name="Failed Attempts")
        .sort_values("Failed Attempts", ascending=False)
    )

    bar_colours = [
        CLR_WARNING if ip in suspicious_ips else CLR_DANGER
        for ip in df_failed_ips["IP Address"]
    ]

    fig2 = go.Figure()
    fig2.add_trace(go.Bar(
        x=df_failed_ips["IP Address"],
        y=df_failed_ips["Failed Attempts"],
        marker_color=bar_colours,
        text=df_failed_ips["Failed Attempts"],
        textposition="outside",
        textfont=dict(color=CLR_TEXT),
        hovertemplate="<b>%{x}</b><br>Failed Attempts: %{y}<extra></extra>",
    ))
    # Draw threshold line
    fig2.add_shape(
        type="line",
        x0=-0.5, x1=len(df_failed_ips) - 0.5,
        y0=effective_threshold, y1=effective_threshold,
        line=dict(color=CLR_WARNING, width=1.5, dash="dash"),
    )
    fig2.add_annotation(
        x=len(df_failed_ips) - 1,
        y=effective_threshold + 0.15,
        text=f"Threshold ({effective_threshold})",
        showarrow=False,
        font=dict(color=CLR_WARNING, size=11),
        xanchor="right",
    )
    fig2.update_layout(
        **PLOT_LAYOUT,
        title=dict(text="Failed Logins per IP Address (sample)", font=dict(color=CLR_TEXT, size=13)),
        xaxis=dict(title="IP Address", title_font=dict(color=CLR_MUTED), tickfont=dict(color=CLR_TEXT)),
        yaxis=dict(
            title="Failed Attempts",
            title_font=dict(color=CLR_MUTED),
            gridcolor=CLR_BORDER,
            dtick=1,
        ),
        showlegend=False,
        height=320,
    )
    st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # ── Chart 3: Login outcomes over time ─────────────────────────────────────
    st.markdown("**3 · Login Outcomes Over Time**")
    st.caption(
        "Shows each login attempt plotted against its timestamp. "
        "The cluster of red dots within seconds of each other is the brute-force burst."
    )

    df_time = df_all.copy()
    df_time["Colour"] = df_time["Result"].map({"Success": CLR_SUCCESS, "Failed": CLR_DANGER})
    df_time["Label"]  = df_time["Result"]

    fig3 = go.Figure()
    for result, colour in [("Success", CLR_SUCCESS), ("Failed", CLR_DANGER)]:
        sub = df_time[df_time["Result"] == result]
        fig3.add_trace(go.Scatter(
            x=sub["Time"],
            y=sub["Result"],
            mode="markers",
            name=result,
            marker=dict(color=colour, size=10, opacity=0.85, symbol="circle"),
            text=sub["Username"] + " · " + sub["IP Address"],
            hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
        ))
    fig3.update_layout(
        **PLOT_LAYOUT,
        title=dict(text="Login Attempts Over Time (sample)", font=dict(color=CLR_TEXT, size=13)),
        xaxis=dict(
            title="Time",
            title_font=dict(color=CLR_MUTED),
            gridcolor=CLR_BORDER,
            tickfont=dict(color=CLR_TEXT),
        ),
        yaxis=dict(
            title="Outcome",
            title_font=dict(color=CLR_MUTED),
            tickfont=dict(color=CLR_TEXT),
            gridcolor=CLR_BORDER,
        ),
        height=280,
    )
    st.plotly_chart(fig3, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION D — SECURITY ALERTS
# ══════════════════════════════════════════════════════════════════════════════
elif section == "Security Alerts":

    st.markdown('<p class="cs-section-title">Security Alerts — Rule-Based Detection</p>', unsafe_allow_html=True)

    # Disclaimer
    st.markdown(
        '<div class="cs-disclaimer">'
        "<b>Important context:</b> A suspicious login pattern does <b>not</b> automatically prove a "
        "cyberattack. The same pattern can result from a user forgetting their password, a "
        "misconfigured application, or a test script. These alerts are a starting point for "
        "human investigation — not a final verdict. All data shown is simulated."
        "</div>",
        unsafe_allow_html=True,
    )

    # Expandable: how the detection rule works
    with st.expander("How the detection rule works"):
        st.markdown(f"""
**Rule:** If the same IP address produces **{effective_threshold} or more failed login attempts**
in the sample records, it is flagged as suspicious.

**Step-by-step:**
1. Loop through every record. For each `Failed` result, increment a counter for that IP address.
2. After processing all records, check each IP's counter against the threshold.
3. IPs at or above the threshold are added to the alerts list.
4. Each alert is assigned a **risk level** based on its count:
   - **High**: 10 or more failures
   - **Medium**: 5–9 failures (current threshold)
   - **Low**: below threshold (not currently shown)

**Limitation:** This is a simple count-based rule for educational purposes. Real-world
security systems use time windows, behavioural baselines, and machine learning to reduce
false positives.
        """)

    # ── Filter ────────────────────────────────────────────────────────────────
    risk_filter = st.selectbox(
        "Filter by Risk Level",
        ["All", "High", "Medium", "Low"],
        help="Show only alerts that match the selected risk level.",
    )

    filtered_alerts = (
        ALERTS if risk_filter == "All"
        else [a for a in ALERTS if a["risk"] == risk_filter]
    )

    if not filtered_alerts:
        if not ALERTS:
            st.success("No IPs met the detection threshold in the sample records. All activity appears normal.")
        else:
            st.info(f"No **{risk_filter} Risk** alerts in the current records. Try selecting 'All'.")
    else:
        st.caption(
            f"Showing {len(filtered_alerts)} of {len(ALERTS)} alert(s) · "
            f"Filter: {risk_filter} · Threshold: ≥ {effective_threshold} failures"
        )

        for alert in filtered_alerts:
            risk   = alert["risk"]
            cls    = f"cs-alert-{risk.lower()}"
            badge  = f"cs-badge-{risk.lower()}"
            colour = {"High": CLR_DANGER, "Medium": CLR_WARNING, "Low": CLR_SUCCESS}[risk]

            # Render the alert card
            st.markdown(f"""
            <div class="cs-alert {cls}">
                <div class="cs-alert-header">
                    <p class="cs-alert-title">Suspicious Login Activity</p>
                    <span class="cs-badge {badge}">{risk} Risk</span>
                </div>
                <div class="cs-alert-grid">
                    <p class="cs-alert-kv"><span class="k">IP Address </span>
                        <span class="v">{alert["ip"]}</span></p>
                    <p class="cs-alert-kv"><span class="k">Target Username </span>
                        <span class="v">{alert["username"]}</span></p>
                    <p class="cs-alert-kv"><span class="k">Failed Attempts </span>
                        <span class="v" style="color:{colour};">{alert["fail_count"]}</span></p>
                    <p class="cs-alert-kv"><span class="k">Risk Level </span>
                        <span class="v" style="color:{colour};">{risk}</span></p>
                    <p class="cs-alert-kv"><span class="k">First Attempt </span>
                        <span class="v">{alert["first_time"]}</span></p>
                    <p class="cs-alert-kv"><span class="k">Last Attempt </span>
                        <span class="v">{alert["last_time"]}</span></p>
                </div>
                <div class="cs-alert-note">
                    <b>Detection reason:</b> {alert["reason"]}<br><br>
                    <b>Suggested investigation steps:</b><br>{alert["investigation"]}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Expandable raw details
            with st.expander(f"View full details for {alert['ip']}"):
                st.markdown(f"""
| Field | Value |
|---|---|
| IP Address | `{alert["ip"]}` |
| Username | `{alert["username"]}` |
| Failed Attempts | `{alert["fail_count"]}` |
| Risk Level | `{risk}` |
| Detection Threshold | `≥ {effective_threshold}` |
| First Attempt | `{alert["first_time"]}` |
| Last Attempt | `{alert["last_time"]}` |
                """)
                st.markdown("**All records from this IP:**")
                ip_records = df_all[df_all["IP Address"] == alert["ip"]].copy()
                ip_records["Time"] = ip_records["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
                st.dataframe(ip_records, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(
    '<div class="cs-footer">'
    "CyberShield v2.0 &nbsp;·&nbsp; Demo Environment &nbsp;·&nbsp; "
    "All data is simulated and fictional &nbsp;·&nbsp; "
    "Not connected to any real network or system"
    "</div>",
    unsafe_allow_html=True,
)
