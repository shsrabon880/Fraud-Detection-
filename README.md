# Fraud Detection & IP Risk Analysis Platform

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Bootstrap 5](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-4.4-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)
![Leaflet.js](https://img.shields.io/badge/Leaflet-1.9-199900?style=for-the-badge&logo=leaflet&logoColor=white)

An enterprise-grade **Fraud Detection, IP Threat Intelligence, and Bank Transaction Monitoring Platform** designed for Security Operations Centers (SOC), fraud analytics teams, and university CSE projects.

The platform provides dual-engine intelligence:
1. **Network IP Threat Intelligence**: Evaluates IPv4 and IPv6 addresses across AbuseIPDB reputation, TOR exit relays, VPN/proxies, datacenter hostings, velocity anomalies, and **Scikit-Learn Machine Learning (Random Forest)** fraud risk inference.
2. **Connect Bank Account & Transaction Monitoring**: Authorizes secure Open Banking connections, retrieves user-consented transaction feeds, and correlates banking transactions directly with IP origin risk intelligence to flag fraudulent wires, proxy hops, and geographic impossibilities in real time.

---

## 📸 Key Capabilities & Architecture

- **Modern Cyber UI**: Dark navy/black theme with high-tech glassmorphism cards, glowing neon risk accents, and responsive layout.
- **Connect Bank Account**: Dedicated bank connection portal with support for 8 major banking institutions (JPMorgan Chase, Bank of America, Wells Fargo, Citibank, Barclays, Capital One, HSBC, Revolut).
- **Masked Account Display**: Strict data protection displaying accounts as `•••• •••• •••• 4892`.
- **Zero-Trust Password Policy (Req 11)**: Adheres to Open Banking OAuth 2.0 standards. The platform **never** asks for, collects, or stores bank login passwords, debit card PINs, or SMS OTPs.
- **Demo Mode Sandbox (Req 12)**: When official bank API credentials are not set, activates high-fidelity Demo Mode with realistic simulated accounts and synthetic transactions. Simulated accounts are strictly badged and never portrayed as real accounts.
- **Transaction Monitoring Module**: Correlates user-consented banking transactions with IP threat scores, flagging high-risk Tor nodes, foreign proxies, and anomaly amounts.
- **Leaflet.js Geolocation Map**: Interactive world map with watermark-free dark CartoDB tiles and animated radar pulsing pinpoint on the IP's coordinates.
- **Dual Database Architecture**: Full production support for **MySQL** (`schema.sql`) with **instant automatic fallback to SQLite**, allowing zero-config evaluation out of the box.

---

## 📂 Project Directory Structure

```
d:\Anty Gravity/
├── app.py                      # Flask backend entrypoint & REST API endpoints
├── config.py                   # App configuration, environment loader, DB credentials
├── init_db.py                  # Database diagnostic and schema verification utility
├── test_api.py                 # Automated unit and integration test suite (12 tests)
├── requirements.txt            # Python dependencies
├── schema.sql                  # MySQL database schema (DDL & seed sample data)
├── .env.example                # Sample environment variables template
├── .env                        # Local active environment configuration
├── database/
│   ├── __init__.py
│   ├── db.py                   # Dual-engine Database Manager (MySQL with auto-SQLite fallback)
│   ├── models.py               # Data Access Objects (analyses, security_actions, bank_connections, transactions)
│   └── fraud_detection.db      # SQLite local database (generated automatically)
├── services/
│   ├── __init__.py
│   ├── bank_service.py         # Bank OAuth 2.0 workflow & consented transaction generator
│   ├── ip_intelligence.py      # AbuseIPDB & IPinfo client with deterministic simulation fallback
│   ├── risk_scorer.py          # Multi-factor hybrid weighted scoring engine
│   ├── ml_detector.py          # Scikit-Learn Random Forest fraud classifier
│   └── model/
│       └── ip_risk_model.joblib # Serialized trained ML model (120 decision trees)
├── static/
│   ├── css/
│   │   └── style.css           # Cybersecurity dark UI theme, animations, radar pulses
│   └── js/
│       ├── api.js              # REST client wrapper
│       ├── charts.js           # Chart.js gauge & 6-axis threat radar
│       ├── map.js              # Leaflet.js interactive dark cyber map
│       └── app.js              # Application reactivity, DOM binding, modals
└── templates/
    ├── index.html              # Main IP Fraud & Risk Analysis Dashboard (with Sidebar)
    ├── bank.html               # Dedicated Connect Bank Account Page (Req 2)
    └── transactions.html       # Transaction Monitoring & Fraud Detection Module (Req 9)
```

---

## 🏦 Connect Bank Account & Transaction Monitoring Workflow

```
       ┌────────────────────────┐
       │   Select Bank          │ (JPMorgan Chase, Bank of America, Wells Fargo, etc.)
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │   OAuth 2.0 Consent    │ User grants read-only scopes (90-day history, masked account)
       │  (Zero Password Policy)│ *Strictly NO passwords, PINs, or OTPs collected (Req 11)*
       └───────────┬────────────┘
                   │
                   ├─── Official Bank API (When credentials present)
                   └─── Demo Mode Sandbox (When credentials absent - Req 12)
                   │
                   ▼
       ┌────────────────────────┐
       │ Connected Account Card │ Displays masked number (•••• 4892) & Status: CONNECTED
       │ (With Disconnect Opt)  │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ Consented Transactions │ Feeds into Transaction Monitoring Module
       │   Stream & IP Scoring  │ Cross-references Origin IP with Tor/VPN/Bot ML Scorer
       └────────────────────────┘
```

---

## 🚀 Setup & Installation Instructions

### Step 1: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 2: Configure Environment (Optional)
Check `.env`:
```ini
# MySQL Configuration (Leave defaults for local XAMPP/MySQL or SQLite auto-fallback)
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=fraud_detection_db
DB_USER=root
DB_PASSWORD=

# IP Threat APIs (Blank = High-fidelity simulation mode active)
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=

# Bank API Configuration (Blank = Demo Mode sandbox active)
BANK_API_CLIENT_ID=
BANK_API_SECRET=
BANK_API_ENV=sandbox
```

### Step 3: Run Database Diagnostic
```powershell
python init_db.py
```

### Step 4: Start the Dashboard
```powershell
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 🧭 Navigating the Dashboard Pages

1. **IP Risk Analysis (`/`)**:
   - Live IP threat scanning, colorful Risk Score Gauge (0–100), Leaflet world map with pinpoint radar, and 6-axis threat radar.
   - Quick preset buttons: `8.8.8.8` (Clean), `185.220.101.5` (Tor Exit Relay - Malicious), `198.51.100.84` (FastFlux Proxy - High).
2. **Connect Bank Account (`/bank`)**:
   - View connected account information with masked account numbers (`•••• •••• •••• 4892`).
   - Check connection status (`CONNECTED` / `DISCONNECTED`).
   - Disconnect or reconnect bank account with 1 click.
   - Select and authorize other banking institutions.
3. **Transaction Monitoring (`/transactions`)**:
   - Inspects user-consented transaction stream.
   - Highlights flagged fraudulent transactions (e.g., transactions originating from Tor exit relays).
   - Click "Analyze IP" on any transaction to inspect the origin IP in the IP Risk engine!

---

## 🧪 Running Automated Tests

Run the full 12-test integration suite:

```powershell
python test_api.py
```

Expected output:
```
test_01_index_page ... ok
test_02_config_endpoint ... ok
test_03_stats_endpoint ... ok
test_04_analyze_clean_ip ... ok
test_05_analyze_malicious_tor_ip ... ok
test_06_invalid_ip_validation ... ok
test_07_security_action_authorization_enforcement ... ok
test_08_history_and_export ... ok
test_09_bank_institutions_and_pages ... ok
test_10_bank_connect_authorization_demo_mode ... ok
test_11_consented_transactions_and_monitoring ... ok
test_12_bank_disconnect_and_reconnect ... ok
----------------------------------------------------------------------
Ran 12 tests in 0.132s
OK
```

---

## 📜 License
Developed for educational, research, and enterprise threat intelligence demonstrations.
Distributed under the MIT License.
