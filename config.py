import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Load .env file
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-fraud-detector-key-2026")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    PORT = int(os.getenv("PORT", 5000))

    # MySQL Configuration
    DB_TYPE = os.getenv("DB_TYPE", "mysql").lower()
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_NAME = os.getenv("DB_NAME", "fraud_detection_db")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")

    # SQLite Fallback Path
    SQLITE_DB_PATH = BASE_DIR / os.getenv("SQLITE_DB_PATH", "database/fraud_detection.db")

    # API Keys
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()
    SIMULATION_MODE = os.getenv("SIMULATION_MODE", "false").lower() in ("true", "1", "yes")

    # Bank API / Open Banking Configuration
    BANK_API_CLIENT_ID = os.getenv("BANK_API_CLIENT_ID", "").strip()
    BANK_API_SECRET = os.getenv("BANK_API_SECRET", "").strip()
    BANK_API_ENV = os.getenv("BANK_API_ENV", "sandbox").strip()

    # ML Model directory
    MODEL_DIR = BASE_DIR / "services" / "model"
    MODEL_PATH = MODEL_DIR / "ip_risk_model.joblib"

    # API Endpoints
    ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
    IPINFO_URL_TEMPLATE = "https://ipinfo.io/{ip}/json"
