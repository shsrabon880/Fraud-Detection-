import os
import csv
import io
import json
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from config import Config
from database.db import db_mgr
from database.models import IPAnalysisModel, BankModel
from services.ip_intelligence import IPIntelligenceService
from services.risk_scorer import RiskScorer
from services.ml_detector import ml_fraud_detector
from services.bank_service import BankService

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# ============================================================================
# PAGE ROUTES
# ============================================================================

@app.route("/")
def index():
    """Renders the main Fraud Detection & IP Risk Analysis Dashboard."""
    return render_template("index.html")

@app.route("/bank")
def bank_page():
    """Renders the dedicated Connect Bank Account page (Requirement 2)."""
    return render_template("bank.html")

@app.route("/transactions")
def transactions_page():
    """Renders the Transaction Monitoring & Fraud Detection module (Requirement 9)."""
    return render_template("transactions.html")

# ============================================================================
# IP RISK ANALYSIS REST API ENDPOINTS
# ============================================================================

@app.route("/api/config", methods=["GET"])
def get_config_status():
    """Returns runtime intelligence sources, bank API, and database status."""
    is_bank_live = BankService.is_official_api_configured()
    return jsonify({
        "status": "online",
        "database": {
            "engine": "MySQL" if db_mgr.mysql_available else "SQLite (Fallback Active)",
            "host": Config.DB_HOST if db_mgr.mysql_available else "Local File",
            "name": Config.DB_NAME if db_mgr.mysql_available else os.path.basename(Config.SQLITE_DB_PATH)
        },
        "intelligence": {
            "abuseipdb_configured": bool(Config.ABUSEIPDB_API_KEY),
            "ipinfo_configured": bool(Config.IPINFO_TOKEN),
            "simulation_mode_forced": Config.SIMULATION_MODE,
            "active_mode": "Live APIs" if (not Config.SIMULATION_MODE and (Config.ABUSEIPDB_API_KEY or Config.IPINFO_TOKEN)) else "High-Fidelity Simulation"
        },
        "bank_api": {
            "is_live_configured": is_bank_live,
            "mode": "Official Bank API" if is_bank_live else "Demo Mode (Simulated Sandbox)",
            "environment": Config.BANK_API_ENV
        },
        "machine_learning": {
            "model_type": "Scikit-Learn RandomForestClassifier",
            "accuracy": f"{ml_fraud_detector.accuracy * 100:.2f}%",
            "features_evaluated": len(ml_fraud_detector.FEATURE_NAMES)
        }
    })

@app.route("/api/analyze", methods=["POST"])
def analyze_ip():
    """
    Main IP analysis endpoint. Validates IP, aggregates intelligence,
    runs ML fraud model, scores risk, saves to DB, and returns structured analysis.
    """
    data = request.get_json(silent=True) or {}
    ip_input = data.get("ip", "").strip()

    if not ip_input:
        return jsonify({"success": False, "error": "Please provide an IP address to analyze."}), 400

    # 1. Validation
    is_valid, version, is_private, err_msg = IPIntelligenceService.validate_ip(ip_input)
    if not is_valid:
        return jsonify({"success": False, "error": err_msg}), 400

    force_refresh = data.get("refresh", False)

    # 2. Check Cache if not forced refresh
    if not force_refresh:
        cached_result = IPAnalysisModel.get_cached_ip(ip_input)
        if cached_result:
            cached_result["from_cache"] = True
            return jsonify({"success": True, "data": cached_result})

    try:
        # 3. Fetch IP Intelligence
        intel_data = IPIntelligenceService.fetch_ip_intelligence(ip_input)

        # 4. Score Risk with Multi-Factor Engine & Scikit-Learn ML Model
        risk_result = RiskScorer.calculate_risk(intel_data)

        # 5. Assemble Comprehensive Analysis Payload
        analysis_payload = {
            "ip_address": intel_data["ip_address"],
            "ip_version": intel_data["ip_version"],
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "risk_color": risk_result["risk_color"],
            "risk_badge": risk_result["risk_badge"],
            "abuse_confidence_score": intel_data["abuse_confidence_score"],
            "total_reports": intel_data["total_reports"],
            "distinct_users": intel_data["distinct_users"],
            "is_vpn": intel_data["is_vpn"],
            "is_tor": intel_data["is_tor"],
            "is_hosting": intel_data["is_hosting"],
            "is_attacker": intel_data["is_attacker"],
            "is_spam": intel_data["is_spam"],
            "is_bot": intel_data["is_bot"],
            "is_anonymous": intel_data["is_anonymous"],
            "blacklist_status": intel_data["blacklist_status"],
            "bot_activity": intel_data.get("bot_activity", "Unknown"),
            "unusual_traffic": intel_data.get("unusual_traffic", "Unknown"),
            "velocity_checks": intel_data.get("velocity_checks", "Unknown"),
            "country_code": intel_data.get("country_code", "Unknown"),
            "country_name": intel_data.get("country_name", "Unknown"),
            "region": intel_data.get("region", "Unknown"),
            "city": intel_data.get("city", "Unknown"),
            "latitude": intel_data.get("latitude", 0.0),
            "longitude": intel_data.get("longitude", 0.0),
            "timezone": intel_data.get("timezone", "UTC"),
            "asn": intel_data.get("asn", "Unknown"),
            "asn_name": intel_data.get("asn_name", "Unknown"),
            "isp": intel_data.get("isp", "Unknown"),
            "connection_type": intel_data.get("connection_type", "Unknown"),
            "usage_type": intel_data.get("usage_type", "Unknown"),
            "domain_name": intel_data.get("domain_name", "Unknown"),
            "ip_age": intel_data.get("ip_age", "Unknown"),
            "last_seen_date": intel_data.get("last_seen_date", "Unknown"),
            "ml_analysis": risk_result["ml_analysis"],
            "ml_risk_probability": risk_result["ml_analysis"]["ml_risk_probability"],
            "ml_predicted_label": risk_result["ml_analysis"]["ml_predicted_label"],
            "recommendation": risk_result["recommendation"],
            "recommendation_summary": risk_result["recommendation"]["summary"],
            "radar_breakdown": risk_result["radar_breakdown"],
            "vectors": risk_result["vectors"],
            "is_simulated": intel_data.get("is_simulated", False),
            "intelligence_source": intel_data.get("intelligence_source", "Intelligence Engine"),
            "from_cache": False
        }

        # 6. Save Analysis to Database
        try:
            db_record_id = IPAnalysisModel.save_analysis({
                **analysis_payload,
                "raw_data_json": analysis_payload
            })
            analysis_payload["id"] = db_record_id
        except Exception as dbe:
            print(f"[DB Warning] Failed saving analysis record: {dbe}")

        # 7. Cache in-memory/DB cache
        IPAnalysisModel.cache_ip(ip_input, analysis_payload, ttl_hours=4)

        return jsonify({"success": True, "data": analysis_payload})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Analysis failed: {str(e)}"}), 500

@app.route("/api/history", methods=["GET"])
def get_history():
    """Retrieves recent IP analysis records with optional risk filtering and search."""
    limit = request.args.get("limit", 50, type=int)
    level = request.args.get("level", None)
    search = request.args.get("search", None)

    try:
        records = IPAnalysisModel.get_history(limit=limit, filter_level=level, search=search)
        return jsonify({"success": True, "records": records, "count": len(records)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieves aggregated metrics for the top dashboard statistics."""
    try:
        stats = IPAnalysisModel.get_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/action", methods=["POST"])
def security_action():
    """
    Complies with Security Requirement 6:
    Blocking must require explicit authorization and confirmation.
    Never blocks automatically without human confirmation.
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    action = data.get("action", "").upper().strip()
    reason = data.get("reason", "").strip()
    operator = data.get("operator", "Security Analyst").strip()
    confirmed = bool(data.get("confirmed", False))

    if not ip:
        return jsonify({"success": False, "error": "IP address is required."}), 400
    if action not in ("BLOCK", "ALLOW", "FLAG", "UNBLOCK"):
        return jsonify({"success": False, "error": f"Invalid action: {action}"}), 400
    if not confirmed:
        return jsonify({"success": False, "error": "Security requirement: Action requires explicit authorization confirmation."}), 403
    if not reason:
        reason = f"Manual {action} action applied via Security Operations Dashboard."

    score = data.get("risk_score", 0)
    level = data.get("risk_level", "UNKNOWN")

    try:
        log_id = IPAnalysisModel.log_security_action(
            ip_address=ip,
            action_type=action,
            risk_score=score,
            risk_level=level,
            reason=reason,
            operator_name=operator,
            metadata={"source": "Dashboard UI Modal"}
        )
        return jsonify({
            "success": True,
            "message": f"IP {ip} has been successfully recorded with status: {action}",
            "log_id": log_id,
            "action": action,
            "ip": ip,
            "operator": operator
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/actions", methods=["GET"])
def get_actions_log():
    """Retrieves security action audit logs."""
    limit = request.args.get("limit", 20, type=int)
    try:
        logs = IPAnalysisModel.get_security_actions(limit=limit)
        return jsonify({"success": True, "actions": logs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/export", methods=["GET"])
def export_history():
    """Exports all IP analysis history to CSV or JSON format."""
    export_format = request.args.get("format", "csv").lower()
    records = IPAnalysisModel.get_history(limit=1000)

    if export_format == "json":
        return Response(
            json.dumps(records, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=ip_fraud_analysis_export.json"}
        )

    # Export CSV
    output = io.StringIO()
    if records:
        fieldnames = [
            "id", "ip_address", "ip_version", "risk_score", "risk_level",
            "abuse_confidence_score", "total_reports", "is_vpn", "is_tor", "is_hosting",
            "is_attacker", "is_spam", "country_name", "city", "isp", "asn",
            "ml_risk_probability", "ml_predicted_label", "created_at"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in records:
            writer.writerow(r)
    else:
        output.write("No records to export\n")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=ip_fraud_analysis_export.csv"}
    )

# ============================================================================
# CONNECT BANK ACCOUNT & TRANSACTION MONITORING REST APIS
# ============================================================================

@app.route("/api/bank/status", methods=["GET"])
def get_bank_status():
    """Returns currently connected bank account metadata, masked account numbers, and status."""
    conn = BankService.get_current_connection()
    is_live = BankService.is_official_api_configured()
    return jsonify({
        "success": True,
        "is_configured": is_live,
        "mode": "Official Bank API" if is_live else "Demo Mode (Simulated Sandbox)",
        "connection": conn
    })

@app.route("/api/bank/institutions", methods=["GET"])
def get_bank_institutions():
    """Returns list of supported banks with selection metadata (Req 3)."""
    banks = BankService.get_supported_banks()
    is_live = BankService.is_official_api_configured()
    return jsonify({
        "success": True,
        "is_live": is_live,
        "mode": "Live Official API" if is_live else "Demo Mode (Simulated Sandbox)",
        "banks": banks
    })

@app.route("/api/bank/connect", methods=["POST"])
def connect_bank():
    """
    Authorizes bank connection via OAuth / Demo workflow.
    Complies with Requirements 4, 5, 8, 10, 11, 12:
    - Never collects passwords, PINs, or OTPs.
    - Uses masked account numbers.
    - Clearly marks simulated demo accounts if no official API is set.
    """
    data = request.get_json(silent=True) or {}
    institution_id = data.get("institution_id")
    account_type = data.get("account_type", "Checking")
    scopes = data.get("scopes", "read_accounts,read_transactions_90d,read_balance")

    if not institution_id:
        return jsonify({"success": False, "error": "Bank institution is required."}), 400

    try:
        conn_data = BankService.authorize_connection(institution_id, scopes, account_type)
        return jsonify({
            "success": True,
            "message": f"Successfully authorized connection with {conn_data['institution_name']}.",
            "connection": conn_data
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bank/disconnect", methods=["POST"])
def disconnect_bank():
    """Revokes bank authorization and sets status to DISCONNECTED (Req 6 & 7)."""
    data = request.get_json(silent=True) or {}
    conn_id = data.get("connection_id")
    try:
        BankService.disconnect_connection(conn_id)
        return jsonify({
            "success": True,
            "message": "Bank account has been disconnected and data sharing has been revoked."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bank/reconnect", methods=["POST"])
def reconnect_bank():
    """Restores bank connection status to CONNECTED (Req 6)."""
    data = request.get_json(silent=True) or {}
    conn_id = data.get("connection_id")
    try:
        BankService.reconnect_connection(conn_id)
        return jsonify({
            "success": True,
            "message": "Bank connection restored successfully."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bank/transactions", methods=["GET"])
def get_bank_transactions():
    """
    Retrieves user-consented transactions for Transaction Monitoring (Req 8 & 9).
    Includes origin IP address risk evaluation and fraud diagnostics.
    """
    fraud_filter = request.args.get("status")
    limit = request.args.get("limit", 50, type=int)

    conn = BankService.get_current_connection()
    # Auto-seed initial demo connection if totally fresh so user can evaluate immediately
    if not conn:
        conn = BankService.authorize_connection("chase")

    conn_id = conn["id"] if conn else None
    transactions = BankModel.get_transactions(connection_id=conn_id, limit=limit, fraud_filter=fraud_filter)
    stats = BankModel.get_transaction_stats(connection_id=conn_id)

    return jsonify({
        "success": True,
        "connection": conn,
        "transactions": transactions,
        "stats": stats
    })

if __name__ == "__main__":
    print(f"============================================================")
    print(f"  FRAUD DETECTION & IP RISK ANALYSIS DASHBOARD")
    print(f"  Active Database : {'MySQL' if db_mgr.mysql_available else 'SQLite (Automatic Fallback)'}")
    print(f"  Bank API Mode   : {'Official API' if BankService.is_official_api_configured() else 'Demo Mode (Simulated Sandbox)'}")
    print(f"  ML Risk Model   : RandomForestClassifier (Accuracy: {ml_fraud_detector.accuracy*100:.1f}%)")
    print(f"  Local Server    : http://127.0.0.1:{Config.PORT}")
    print(f"============================================================")
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)
