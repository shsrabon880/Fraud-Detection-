"""
Database Initialization & Diagnostic Utility
Fraud Detection & IP Risk Analysis Dashboard
"""
import os
import sys
from config import Config
from database.db import db_mgr
from database.models import IPAnalysisModel, BankModel
from services.bank_service import BankService

def main():
    print("=" * 65)
    print("  FRAUD DETECTION SYSTEM - DATABASE INITIALIZATION & DIAGNOSTICS")
    print("=" * 65)

    print(f"Target DB Type : {Config.DB_TYPE.upper()}")
    print(f"MySQL Host     : {Config.DB_HOST}:{Config.DB_PORT}")
    print(f"MySQL Database : {Config.DB_NAME}")
    print(f"SQLite Path    : {Config.SQLITE_DB_PATH}")
    print(f"Bank API Mode  : {'Live Official API' if BankService.is_official_api_configured() else 'Demo Mode (Simulated Sandbox)'}")
    print("-" * 65)

    if db_mgr.mysql_available:
        print("[SUCCESS] MySQL server connected and verified.")
    else:
        print("[NOTICE] Running with SQLite local database (Zero-config mode).")

    stats = IPAnalysisModel.get_stats()
    bank_stats = BankModel.get_transaction_stats()
    bank_conn = BankModel.get_active_connection()

    print("-" * 65)
    print("Current Database Status:")
    print(f"  - Total IP Analyses Logged : {stats['total_scanned']}")
    print(f"  - High Risk IPs            : {stats['high_risk']}")
    print(f"  - Medium Risk IPs          : {stats['medium_risk']}")
    print(f"  - Low Risk IPs             : {stats['low_risk']}")
    print(f"  - Total Blocks Recorded    : {stats['blocked_count']}")
    print(f"  - Active Storage Engine    : {stats['database_engine']}")
    print(f"  - Connected Bank Account   : {bank_conn['institution_name'] if bank_conn else 'None'} ({bank_conn['masked_account_number'] if bank_conn else '--'})")
    print(f"  - Bank Feed Status         : {bank_conn['connection_status'] if bank_conn else 'DISCONNECTED'}")
    print(f"  - Monitored Transactions   : {bank_stats['total_transactions']} (${bank_stats['total_volume']:,.2f})")
    print("-" * 65)
    print("[READY] The database is fully initialized and ready to accept requests.")
    print("Start the dashboard with: python app.py")
    print("=" * 65)

if __name__ == "__main__":
    main()
