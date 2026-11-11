# Fraud Detection & IP Risk Analysis Platform

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Bootstrap 5](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-4.4-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)
![Leaflet.js](https://img.shields.io/badge/Leaflet-1.9-199900?style=for-the-badge&logo=leaflet&logoColor=white)

An enterprise-grade **Fraud Detection, IP Threat Intelligence, and Bank / MFS Transaction Monitoring Platform** designed for Security Operations Centers (SOC), fraud analytics teams, and university CSE projects.

The platform provides dual-engine intelligence:
1. **Network IP Threat Intelligence**: Evaluates IPv4 and IPv6 addresses across AbuseIPDB reputation, TOR exit relays, VPN/proxies, datacenter hostings, velocity anomalies, and **Scikit-Learn Machine Learning (Random Forest)** fraud risk inference.
2. **Connect Bank & Online Banking / MFS Account**: Authorizes secure Open Banking connections and **Bangladesh Mobile Financial Services (bKash, Nagad, Rocket)**, retrieves user-consented transaction feeds, and correlates banking transactions directly with IP origin risk intelligence to flag fraudulent wires, proxy hops, and geographic impossibilities in real time.

---

## 📸 Key Capabilities & Architecture

- **Modern Cyber UI**: Dark navy/black theme with high-tech glassmorphism cards, glowing neon risk accents, and responsive layout.
- **Bangladesh Online Banking / MFS Integration**: Direct support for **bKash** (`bikash`), **Nagad** (`nogod`), and **Rocket (DBBL)** mobile financial services with authentic Bangladeshi currency (BDT ৳) and localized mobile number masking (`+880 17•• •••4892`).
- **Global Commercial Banks**: Support for JPMorgan Chase, Bank of America, Wells Fargo, Citibank, Barclays, Capital One, HSBC, and Revolut.
- **Masked Account Display**: Strict data protection displaying accounts as `+880 17•• •••4892` or `•••• •••• •••• 4892`.
- **Zero-Trust Password Policy (Req 11)**: Adheres to Open Banking OAuth 2.0 standards. The platform **never** asks for, collects, or stores bank login passwords, debit card PINs, MFS PINs, or SMS OTPs.
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
├── test_api.py                 # Automated unit and integration test suite (13 tests)
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
│   ├── bank_service.py         # Bank & MFS (bKash, Nagad, Rocket) workflow & transaction generator
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
    ├── bank.html               # Dedicated Connect Bank / MFS Account Page (Req 2)
    └── transactions.html       # Transaction Monitoring & Fraud Detection Module (Req 9)
```

---

## 🏦 Supported Banking & MFS Providers

| Provider | Type | Country | Currency | Account Number Format |
|---|---|---|---|---|
| **bKash** (`bikash`) | Mobile Financial Service (MFS) | Bangladesh (BD) | BDT (৳) | `+880 17•• •••4892` |
| **Nagad** (`nogod`) | Post Office Digital MFS | Bangladesh (BD) | BDT (৳) | `+880 16•• •••8921` |
| **Rocket** (`rocket`) | DBBL Mobile Banking | Bangladesh (BD) | BDT (৳) | `+880 19•• •••542-8` |
| **JPMorgan Chase** | Commercial / Retail Bank | USA (US) | USD ($) | `•••• •••• •••• 4892` |
| **Bank of America** | Retail & Corporate Bank | USA (US) | USD ($) | `•••• •••• •••• 2190` |
| **Wells Fargo** | Consumer Financial Services | USA (US) | USD ($) | `•••• •••• •••• 7714` |
| **Citibank** | Global Consumer Banking | Global | USD ($) | `•••• •••• •••• 5531` |
| **Barclays** | Open Banking UK Compliant | UK | GBP (£) | `•••• •••• •••• 3098` |
| **Capital One** | Digital Banking & Credit | USA (US) | USD ($) | `•••• •••• •••• 8842` |
| **HSBC** | Multinational Banking | Global | USD ($) | `•••• •••• •••• 6610` |
| **Revolut** | Neobank / Fintech | EU / UK / US | EUR (€) | `•••• •••• •••• 9923` |

---

## 🚀 Quick Setup & Run Instructions

### 1. Prerequisites
- Python 3.11+ installed.
- (Optional) MySQL 8.0 running on localhost:3306. If MySQL is offline, the app automatically runs on local SQLite.

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Initialize Database & Train ML Model
```powershell
python init_db.py
```

### 4. Run Automated Test Suite
```powershell
python test_api.py
```
*(Runs 13 test cases covering IP intelligence, ML scoring, bKash/Nagad/Rocket connection, and transaction monitoring).*

### 5. Launch the Web Application
```powershell
python app.py
```

Open your browser at: **`http://127.0.0.1:5000`**
- IP Risk Analysis Dashboard: `http://127.0.0.1:5000/`
- Connect Bank / MFS Account: `http://127.0.0.1:5000/bank`
- Transaction Monitoring: `http://127.0.0.1:5000/transactions`
