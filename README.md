# 🛡️ CyberShield — Security Monitoring & Threat Detection Dashboard

A beginner-friendly cybersecurity dashboard built with Python and Streamlit. CyberShield
simulates the kind of login-monitoring tool used in a Security Operations Center (SOC) to
detect suspicious activity such as brute-force login attempts.

> **Note:** All data shown in this application is entirely simulated and fictional.
> CyberShield is **not** connected to any real network, database, or live system.
> It is intended for learning, demonstration, and portfolio purposes only.

---

## Overview

Many organisations are targeted by **brute-force attacks**, where an attacker repeatedly
tries different passwords against an account until one works. Without a monitoring tool,
these repeated failed login attempts can go unnoticed.

CyberShield addresses this by:

- Loading a set of simulated login records.
- Scanning those records with a configurable rule-based detection engine.
- Flagging IP addresses that produce too many failed logins.
- Displaying the results through a clean, dark-themed dashboard with metric cards,
  interactive charts, filtered tables, and structured alert cards.

The entire application lives in a single Python file (`app.py`) and requires no database,
no cloud service, and no external API.

---

## Features

### Executive Overview
- Two rows of metric cards on the Overview page.
- The first row shows illustrative aggregate statistics (total logins, successful logins,
  failed logins, suspicious activities) for a larger fictional historical dataset.
- The second row shows statistics calculated directly from the 10 sample records so the
  source of each number is transparent.
- A "Top Suspicious IP Addresses" summary table is shown when alerts are detected.

### Login Activity Table
- Displays all 10 simulated login records in a styled, sortable table.
- A **Flagged** column marks rows from suspicious IP addresses with a `⚠ Suspicious` label.
- Four independent filters that all work together:
  - **Login Result** — Success or Failed
  - **Username** — filter by a specific account
  - **IP Address** — filter by a specific source IP
  - **Free-text search** — searches both username and IP address columns simultaneously
- A **Clear Filters** button that fully resets all four filters to their default values.
- A row-count summary caption that updates in real time as filters are applied.
- A **Download as CSV** button that exports the currently filtered and displayed records.

### Visual Analytics (Plotly charts)
Three interactive Plotly charts, all based on the 10 sample records:

1. **Login Outcome Comparison** — grouped bar chart comparing successful vs failed logins.
2. **Failed Logins by IP Address** — bar chart showing failure counts per IP address.
   Suspicious IPs are highlighted in amber. A dashed threshold line shows exactly where
   the detection rule fires.
3. **Login Outcomes Over Time** — scatter plot of every login attempt on a timeline.
   The brute-force burst appears as a tight cluster of red dots.

All charts include hover tooltips, a consistent dark colour palette, and explanatory captions.

### Rule-Based Detection Engine
- Written in plain Python using loops, dictionaries, and `if` statements — no machine learning.
- **Rule:** if the same IP address produces `N` or more failed login attempts (where `N` is the
  configurable threshold), it is flagged as suspicious.
- Risk levels are assigned by failure count:
  - **High** — 10 or more failures
  - **Medium** — 5–9 failures
  - **Low** — below the threshold (not currently shown as an alert)

### Configurable Detection Threshold
- A number input in the sidebar lets users adjust the threshold between 2 and 20.
- Changing the threshold immediately re-runs the detection engine and updates the metric
  cards, the threshold line on Chart 2, and the Security Alerts section — no page reload needed.

### Security Alerts
- One alert card per flagged IP address, sorted by risk level (High first) then by failure count.
- Each card displays:
  - Risk severity badge (colour-coded)
  - IP address and target username
  - Total failed attempt count
  - Timestamp of the first and last failed attempt
  - A plain-English detection reason
  - Four suggested investigation steps
- A **Filter by Risk Level** dropdown to show only High, Medium, or Low alerts.
- An **expandable "View full details"** panel showing a data table of every record from that IP.
- An expandable **"How the detection rule works"** explanation written in plain English.
- An important disclaimer reminding users that a suspicious pattern is not automatic proof
  of a cyberattack.

### Sidebar
- Section navigation (Overview / Login Activity / Visual Analytics / Security Alerts).
- Configurable detection threshold control.
- A **Reload Data** button that resets the table session state.
- A data disclaimer note.

---

## Screenshots

> *Screenshots not yet included. Run the application locally and take your own using
> `streamlit run app.py`.*

---

## Technology Stack

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11.9 | Core language |
| Streamlit | 1.66.1 | Web UI framework |
| Pandas | 3.0.4 | Data manipulation and filtering |
| Plotly | 7.1.0 | Interactive charts |
| `datetime` | stdlib | Displaying the last-refresh timestamp |

---

## Project Structure

```
project/
├── app.py                          # The entire application (single file)
├── requirements.txt                # Python dependencies
└── cybershield-project-report.html # Submission report (HTML)
```

---

## Prerequisites

- **Python 3.11** or later is recommended. The application was developed and tested on
  Python 3.11.9. It may work on Python 3.9+ but this has not been verified.
- **pip** (comes bundled with Python).
- A terminal or command prompt.
- A modern web browser (Chrome, Edge, Firefox, or Safari).

---

## Installation and Setup

### Windows

```powershell
# 1. Download or clone the project, then open the project folder
cd path\to\project

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Launch the application
streamlit run app.py
```

### Linux / macOS

```bash
# 1. Open the project folder
cd path/to/project

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Launch the application
streamlit run app.py
```

After running the last command, Streamlit will print a local URL such as
`http://localhost:8501`. Open that address in your browser.

---

## How to Use

1. **Open the dashboard** at `http://localhost:8501`.
2. **Use the sidebar** to navigate between the four sections.
3. **Overview** — read the metric cards and the suspicious-IP summary table.
4. **Login Activity** — click **Load / Refresh Sample Data** to display the records.
   Use the filters inside the "Filters & Search" expander to narrow the table.
   Click **Download as CSV** to export the filtered rows.
5. **Visual Analytics** — all three charts load automatically. Hover over bars and dots
   for tooltips. Adjust the threshold in the sidebar to see the dashed line on Chart 2 move.
6. **Security Alerts** — view structured alert cards. Use the **Filter by Risk Level**
   dropdown to focus on a specific severity. Click **View full details** to expand a card.
7. **Clear Filters** in the Login Activity section resets all four filters to their default
   `"All"` / empty state.
8. **Reload Data** in the sidebar resets the table's load state.

---

## Data and Detection Logic

### Data Source
The application uses 10 entirely fictional login records defined as a Python list in
`app.py`. They are not read from a file, database, or network. All usernames, IP addresses,
and timestamps are made up.

A second set of larger aggregate numbers (1,284 total logins, etc.) represents a separate
illustrative historical dataset. These numbers are also hardcoded and are clearly labelled
on the dashboard as "Illustrative aggregate dataset".

### Detection Rule
```
IF (number of failed logins from IP X) >= threshold  →  flag IP X as suspicious
```

The threshold defaults to `5` and is adjustable from the sidebar. The rule is applied by
three helper functions in `app.py`:

- `count_failures_per_ip(records)` — counts failed logins per IP address.
- `get_risk_level(fail_count)` — returns `"High"`, `"Medium"`, or `"Low"` based on count.
- `build_alerts(records, threshold)` — runs both functions and returns a sorted alert list.

### Risk Levels
| Level | Condition |
|---|---|
| High | 10 or more failed attempts |
| Medium | 5–9 failed attempts (at or just above the default threshold) |
| Low | Below the threshold (not shown as an alert by default) |

---

## Limitations

- **No real data.** All records are fictional. The application cannot ingest live logs,
  read files, or connect to any external system.
- **No time-window logic.** The detection rule counts total failures per IP across the
  entire dataset. Five failures spread over a month are treated the same as five failures
  in thirty seconds.
- **No authentication.** The dashboard has no login screen or access control.
- **Single-file, in-memory only.** There is no database, no persistent storage, and no
  multi-user support.
- **Not a production tool.** This project is designed for learning and demonstration.
  It should not be used to make real security decisions.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Run `pip install -r requirements.txt` inside the activated virtual environment. |
| `streamlit: command not found` | Make sure the virtual environment is activated before running the command. |
| Browser shows a blank page | Wait a moment and refresh. Streamlit may still be starting up. |
| Port 8501 already in use | Run `streamlit run app.py --server.port 8502` to use a different port. |
| Filters don't reset when clicking "Clear Filters" | This is fixed in the current version using `st.session_state` key deletion. Ensure you are using the latest `app.py`. |

---

## Future Improvements

The following are potential improvements that have **not** been implemented yet:

- Read login records from a real CSV or log file instead of hardcoded data.
- Add a time-window check (e.g., flag only if 5 failures occur within 5 minutes).
- Support uploading a custom log file through the Streamlit UI.
- Add a geographical IP lookup to map source addresses to countries.
- Implement a dark/light theme toggle.
- Add unit tests for the detection helper functions.
- Export the full alert report as a PDF.

---

## Disclaimer

CyberShield is a **demonstration and educational project** built as part of a cybersecurity
bootcamp. All data is simulated. The application is not connected to any real network,
system, or database, and it does not perform real threat detection. It should not be used as
a production security monitoring tool or to make operational security decisions.

---

## License

No license has been specified for this project. The owner should add a license file before
distributing the project or making it available for reuse under explicit terms. Common
choices include [MIT](https://choosealicense.com/licenses/mit/),
[Apache 2.0](https://choosealicense.com/licenses/apache-2.0/), or
[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/).
