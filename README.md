# 🛡️ WebShield — Security Operations Dashboard

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3-000000?style=flat-square&logo=flask&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-red?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)

**A production-grade cybersecurity monitoring dashboard built with Flask, ML-powered threat detection, and a premium SaaS UI.**

[Live Demo](#running-locally) · [Features](#features) · [API Reference](#api-reference) · [Architecture](#architecture)

</div>

---

## Overview

WebShield is a full-stack web security operations platform that detects, logs, and visualizes cyber attacks in real time. It ingests attack telemetry from tools like **Burp Suite**, **Nmap**, and **custom brute-force scripts**, runs them through a **Random Forest ML classifier**, and presents everything through a clean, dark-mode-capable admin console.

Built as a demonstration of applied cybersecurity engineering — integrating traditional rule-based detection with machine learning classifiers for both **brute-force** and **SQL injection** attack patterns.

---

## Features

### 🔍 Attack Detection
| Feature | Details |
|---|---|
| **Brute Force Detection** | Tracks failed login attempts per IP, time windows, failure rates |
| **SQL Injection Detection** | ML-powered payload analysis on username and password fields |
| **Nmap Scan Logging** | Accepts scan results via REST API |
| **Burp Suite Integration** | Receives proxy findings via webhook endpoint |

### 🤖 Machine Learning
| Feature | Details |
|---|---|
| **Random Forest Classifier** | Trained on labeled brute-force and SQL injection datasets |
| **Confidence Scoring** | Probability scores (0.0–1.0) for every detection |
| **Severity Mapping** | Critical / High / Medium / Low derived from ML probability |
| **Real-time Analysis** | Triggered via dashboard or automatic on login events |

### 📊 Dashboard
- **Admin Dashboard** — Auth stats, doughnut chart, security alerts, live activity feed
- **Attack Stream** — Paginated event log with filter chips, payload side panel
- **ML Analysis** — Detection cards with confidence bars, model status, file upload
- **Log Management** — Scoped deletion with confirmation dialogs

### 🎨 UI/UX
- Light / Dark mode with system preference detection
- Collapsible sidebar with persistent state
- Toast notifications, side panels, confirmation dialogs
- Global search across all visible data
- Full keyboard navigation (arrow keys, Escape, `/` to focus search)
- Responsive: Mobile · Tablet · Desktop · Ultra-wide

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, Flask 2.3, Flask-SQLAlchemy, Flask-CORS |
| **Database** | SQLite (dev) — easily swapped for PostgreSQL/MySQL |
| **ML** | scikit-learn, pandas, numpy, joblib |
| **Frontend** | Vanilla HTML5, CSS3, JavaScript (ES2020+) |
| **Icons** | Font Awesome 6.5 |
| **Charts** | Chart.js |
| **Fonts** | Inter + JetBrains Mono (Google Fonts) |

---

## Architecture

```
WebShield/
├── app.py                    # Flask application, routes, API endpoints
├── ml_service.py             # ML detector wrappers (brute force + SQL injection)
├── requirements.txt
├── .env                      # Environment variables (SECRET_KEY, DB URL, timezone)
│
├── static/
│   ├── css/
│   │   └── theme.css         # Complete design system (tokens, components, layout)
│   └── js/
│       └── theme-toggle.js   # UI runtime (theme, sidebar, menus, toasts, modals)
│
├── templates/
│   ├── base.html             # App shell: sidebar, topbar, navigation
│   ├── login.html            # Auth page (standalone, no base inheritance)
│   ├── admin_dashboard.html  # Login stats, chart, alerts, quick actions
│   ├── dashboard.html        # Attack stream: event log + distribution
│   ├── ml_analysis.html      # ML detections, model status, file upload
│   └── clear_logs.html       # Log management with scoped deletions
│
└── instance/
    └── cybersec_logs.db      # SQLite database (auto-created)
```

### Database Models

```
AttackLog          — Raw attack events (brute force, SQL injection, Nmap, Burp)
LoginAttempt       — Every login attempt with ML prediction fields
MLDetection        — Stored ML classifier results linked to attacks/logins
```

---

## Running Locally

### Prerequisites
- Python 3.10 or newer
- pip

### 1. Clone the repository
```bash
git clone https://github.com/your-username/webshield.git
cd webshield
```

### 2. Create and activate a virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment (optional)
Create a `.env` file (or edit the existing one):
```env
SECRET_KEY=change-this-in-production
DATABASE_URL=sqlite:///cybersec_logs.db
APP_TIMEZONE=Asia/Kolkata
```

### 5. Start the server
```bash
python app.py
```

The app will be available at **http://localhost:5000**

### 6. Login
Use the demo credentials:
- **Username:** `admin`
- **Password:** `admin123`

---

## API Reference

All API routes return JSON. Authentication is session-based (cookie).

### Attack Log Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/logs/brute_force` | Log a brute-force attempt |
| `POST` | `/api/logs/sql_injection` | Log an SQL injection event |
| `POST` | `/api/logs/burp` | Log a Burp Suite finding |
| `POST` | `/api/logs/nmap` | Log an Nmap scan result |

**Example payload (brute force):**
```json
{
  "source_ip": "192.168.1.100",
  "target_url": "/login",
  "target_host": "localhost:5000",
  "payload": "username=admin&password=test123",
  "status_code": 401,
  "method": "POST",
  "severity": "medium",
  "description": "Failed login attempt"
}
```

### Query Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs` | Fetch attack logs (`?type=&limit=`) |
| `GET` | `/api/stats` | Aggregated counts by attack type |
| `GET` | `/api/attack-type-counts` | Count per attack type |
| `GET` | `/api/recent-activity` | Latest login event (for polling) |

### ML Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/ml-status` | Model loaded/offline status |
| `GET` | `/api/ml-stats` | Detection counts by type |
| `GET` | `/api/ml-detections` | Recent ML detection records |
| `POST` | `/api/ml-analyze-json` | Trigger analysis of `brute_force_results.json` |
| `DELETE` | `/api/ml-detections` | Clear all ML detection records |

### Log Management

| Method | Endpoint | Description |
|---|---|---|
| `DELETE` | `/api/clear-logs/brute-force` | Delete brute-force logs and JSON files |
| `DELETE` | `/api/clear-logs/burp-suite` | Delete scanner logs and JSON files |
| `DELETE` | `/api/clear-logs/all` | Delete everything (irreversible) |

---

## Design System

WebShield uses a custom CSS design system (`theme.css`) with:

- **8px spacing grid** — `--s1` (4px) through `--s16` (64px)
- **Color palette** — Blue / Indigo / Cyan / Green / Amber / Red with dark mode variants
- **Typography** — Inter for UI, JetBrains Mono for code
- **Component library** — Buttons, badges, chips, cards, tables, tabs, alerts, toasts, dialogs, side panels, skeletons
- **CSS custom properties** — Full dark/light theming via `[data-theme]` attribute
- **Responsive breakpoints** — 600px, 900px, 1100px, 1920px

---

## Security Notes

> [!WARNING]
> This project is a **security research and educational tool**. Do not deploy with default credentials in production.

- Change `SECRET_KEY` before deploying
- The `admin123` password is intentionally visible for demo purposes
- SQL injection detection may produce false positives for common legitimate usernames
- Every login attempt (including successful ones) is logged to the database

---

## Testing Attacks

Use the included scripts to generate test data:

```bash
# Simulate brute-force attack
python brute_force_attacker.py

# Generate test ML detection records
python generate_test_detections.py

# Check ML detection state
python check_ml_detections.py
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Built with ❤️ as a cybersecurity monitoring demonstration platform.
</div>
