# WebShield

---

## 📌 Project Overview
**WebShield** is a robust, Flask‑based cybersecurity monitoring platform that collects, classifies, and visualises real‑time attack events such as brute‑force attempts, SQL injection, Nmap scans, and Burp Suite findings. The system persists logs in SQLite, enriches them with a pretrained Random‑Forest model for severity scoring, and exposes a clean REST API for seamless integration with external scanning tools.

---

## ✨ Key Features
- **Live Attack Feed** – Real‑time log streaming with auto‑refresh every 15 seconds.
- **Rich Dashboard** – Interactive statistics cards (total logs, critical alerts, unique IPs, per‑attack‑type counts) with glass‑morphism design and dark‑mode support.
- **Extensible API** – Endpoints for brute‑force, SQL injection, Burp Suite, and Nmap logs; plus a summary endpoint for attack‑type counts.
- **Machine‑Learning Classification** – Random‑Forest model automatically assigns severity (low, medium, high, critical).
- **Modular Architecture** – Clear separation of concerns (Flask routes, SQLAlchemy models, front‑end assets).
- **Container‑ready** – Easy to run locally or in production via Gunicorn/UWSGI and Nginx.

---

## 🛠️ Architecture Diagram
```mermaid
graph LR
    subgraph Frontend
        UI[Dashboard UI] -->|fetch| API[/api endpoints]
    end
    subgraph Backend
        Flask[Flask App] -->|ORM| DB[(SQLite / PostgreSQL)]
        Flask -->|ML Model| Classifier[Random‑Forest]
    end
    subgraph External Tools
        Nmap[Nmap Scan] -->|POST JSON| API
        Burp[Burp Suite] -->|POST JSON| API
        Brute[Brute‑Force Script] -->|POST JSON| API
    end
    API --> Flask
```

---

## 🚀 Getting Started
### Prerequisites
- Python 3.9+ 
- `git` (optional, for cloning)
- (Optional) Virtual environment tool (`venv` or `conda`)

### Installation
```bash
# Clone the repository (or navigate to the existing folder)
git clone https://github.com/your‑org/webshield.git
cd webshield

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Initialise the Database
```bash
python -c "from app import db; db.create_all()"
```
A SQLite file `app.db` will be created in the project root.

### Run the Development Server
```bash
python app.py
```
Open your browser at **http://localhost:5000/dashboard**.

---

## 📚 API Reference
| Endpoint | Method | Payload Example | Description |
|----------|--------|----------------|-------------|
| `/api/logs/brute_force` | POST | `{ "source_ip": "1.2.3.4", "target_url": "/login", "payload": "user=admin" }` | Record a brute‑force attempt |
| `/api/logs/sql_injection` | POST | `{ "source_ip": "1.2.3.4", "target_url": "/search", "payload": "id=1 OR 1=1" }` | Record an SQL injection |
| `/api/logs/burp` | POST | `{ "source_ip": "1.2.3.4", "target_url": "/api", "payload": "request body" }` | Record a Burp Suite request |
| `/api/logs/nmap` | POST | `{ "target": "example.com", "scan_type": "-sS", "severity": "medium" }` | Record an Nmap scan |
| `/api/attack-type-counts` | GET | – | Returns JSON with counts per attack type, e.g. `{ "burp": 3, "nmap": 2, "brute_force": 5 }` |
| `/api/stats` | GET | – | Global statistics used by the dashboard (total logs, critical alerts, etc.) |

---

## 📦 Production Deployment
1. **Create a production‑grade WSGI server** (Gunicorn example):
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```
2. **Set environment variables**:
```bash
export FLASK_ENV=production
export DATABASE_URL=postgresql://user:password@db_host/webshield
```
3. **Configure a reverse proxy** (NGINX) to forward traffic to Gunicorn and serve static assets.
4. **Persist the database** – Switch from SQLite to PostgreSQL by updating `SQLALCHEMY_DATABASE_URI` in `app.py`.

---

## 🧪 Testing & Validation
```bash
# Run the test suite (if provided)
pytest tests/

# Simple health‑check
curl -s http://localhost:5000/api/stats | jq
```
Ensure the API returns a 200 status and valid JSON.

---

## 🐞 Troubleshooting
- **No logs appear** – Verify that API requests return `200 OK` and that `app.db` (or your PostgreSQL DB) is writable.
- **Dashboard stats stale** – Confirm the `/api/attack-type-counts` endpoint is reachable; the front‑end polls this endpoint every 15 seconds.
- **Static assets missing** – Run the server from the project root so Flask can locate the `static/` directory.
- **Model loading errors** – Ensure the `model.pkl` file (or equivalent) is present in the root directory and compatible with the installed scikit‑learn version.

---

## 🤝 Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository and create a feature branch.
2. Maintain the existing code style and UI design system.
3. Add or update unit tests for new functionality.
4. Update this README if you introduce breaking changes.
5. Open a Pull Request with a clear description of the changes.

---

## 📄 License
This project is licensed under the **MIT License** – see the `LICENSE` file for details.

---

*Happy shielding!*
