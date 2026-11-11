"""
Integration & Functional Test Suite
Verifies all Main Dashboard sections, REST APIs, ML Model, Bank Connection,
Bangladesh MFS (bKash, Nagad, Rocket), and Transaction Monitoring.
"""
import unittest
import json
from app import app
from database.db import db_mgr

class FraudDashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_01_index_page(self):
        """Test that dashboard loads successfully with HTML content."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"FRAUD DETECTION", response.data)
        self.assertIn(b"Risk Score Gauge", response.data)
        self.assertIn(b"leaflet-map", response.data)
        self.assertIn(b"Connect Bank Account", response.data) # Sidebar option (Req 1)

    def test_02_config_endpoint(self):
        """Test runtime status and security configuration."""
        response = self.client.get("/api/config")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "online")
        self.assertIn("database", data)
        self.assertIn("machine_learning", data)
        self.assertIn("bank_api", data)

    def test_03_stats_endpoint(self):
        """Test aggregated metrics."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("total_scanned", data["stats"])
        self.assertIn("database_engine", data["stats"])

    def test_04_analyze_clean_ip(self):
        """Test analyzing a verified clean IP (Google DNS 8.8.8.8)."""
        response = self.client.post("/api/analyze", json={"ip": "8.8.8.8", "refresh": True})
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertEqual(data["ip_address"], "8.8.8.8")
        self.assertLessEqual(data["risk_score"], 30)
        self.assertEqual(data["risk_level"], "LOW")
        self.assertIn("recommendation", data)
        self.assertIn("ml_analysis", data)
        self.assertIn("radar_breakdown", data)

    def test_05_analyze_malicious_tor_ip(self):
        """Test analyzing a high risk malicious Tor Exit Node (185.220.101.5)."""
        response = self.client.post("/api/analyze", json={"ip": "185.220.101.5", "refresh": True})
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertEqual(data["ip_address"], "185.220.101.5")
        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertEqual(data["is_tor"], "Yes")

    def test_06_invalid_ip_validation(self):
        """Test IPv4 / IPv6 validation rejection."""
        response = self.client.post("/api/analyze", json={"ip": "999.999.999.999"})
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertIn("not a valid", res["error"])

    def test_07_security_action_authorization_enforcement(self):
        """Test Security Requirement: Blocking must require explicit authorization."""
        res_fail = self.client.post("/api/action", json={
            "ip": "185.220.101.5",
            "action": "BLOCK",
            "confirmed": False
        })
        self.assertEqual(res_fail.status_code, 403)

        res_ok = self.client.post("/api/action", json={
            "ip": "185.220.101.5",
            "action": "BLOCK",
            "reason": "Confirmed brute-force attempts on port 22",
            "operator": "Senior Security Analyst",
            "risk_score": 96,
            "risk_level": "HIGH",
            "confirmed": True
        })
        self.assertEqual(res_ok.status_code, 200)
        data = res_ok.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["action"], "BLOCK")

    def test_08_history_and_export(self):
        """Test retrieval of history and export functionality."""
        hist_res = self.client.get("/api/history?limit=10")
        self.assertEqual(hist_res.status_code, 200)
        self.assertTrue(hist_res.get_json()["success"])

        csv_res = self.client.get("/api/export?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.content_type)

        json_res = self.client.get("/api/export?format=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)

    def test_09_bank_institutions_and_pages(self):
        """Test Bank Connection and Transaction Monitoring pages and institutions endpoint (Req 2, 3)."""
        bank_page = self.client.get("/bank")
        self.assertEqual(bank_page.status_code, 200)
        self.assertIn(b"CONNECT", bank_page.data)
        self.assertIn(b"Select Banking Institution", bank_page.data)

        tx_page = self.client.get("/transactions")
        self.assertEqual(tx_page.status_code, 200)
        self.assertIn(b"TRANSACTION", tx_page.data)
        self.assertIn(b"Monitored Transactions", tx_page.data)

        inst_res = self.client.get("/api/bank/institutions")
        self.assertEqual(inst_res.status_code, 200)
        data = inst_res.get_json()
        self.assertTrue(data["success"])
        self.assertGreater(len(data["banks"]), 8)

        # Verify bKash, Nagad, and Rocket are in the supported institutions
        ids = [b["id"] for b in data["banks"]]
        self.assertIn("bkash", ids)
        self.assertIn("nagad", ids)
        self.assertIn("rocket", ids)

    def test_10_bank_connect_authorization_demo_mode(self):
        """Test secure bank authorization, masked numbers, and simulated demo labeling (Req 4, 5, 11, 12)."""
        res = self.client.post("/api/bank/connect", json={
            "institution_id": "chase",
            "account_type": "Checking"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        conn = data["connection"]
        
        # Verify masked account number format (Req 5)
        self.assertTrue(conn["masked_account_number"].startswith("••••"))
        self.assertEqual(conn["connection_status"], "CONNECTED")
        
        # Verify simulated flag in Demo Mode (Req 12)
        self.assertTrue(conn["is_simulated"])
        self.assertIn("auth_token_ref", conn)

    def test_11_consented_transactions_and_monitoring(self):
        """Test user-consented transaction stream and fraud scoring (Req 8, 9)."""
        res = self.client.get("/api/bank/transactions")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertGreater(len(data["transactions"]), 0)
        
        # Verify transaction with Tor IP 185.220.101.5 is flagged for fraud
        flagged_tx = next((t for t in data["transactions"] if t["origin_ip"] == "185.220.101.5"), None)
        self.assertIsNotNone(flagged_tx)
        self.assertEqual(flagged_tx["fraud_status"], "FLAGGED")
        self.assertTrue("Tor" in flagged_tx["fraud_reason"] or "TOR" in flagged_tx["fraud_reason"])

    def test_12_bank_disconnect_and_reconnect(self):
        """Test Disconnect Bank and Reconnect workflow (Req 6, 7)."""
        # Disconnect
        res_disc = self.client.post("/api/bank/disconnect", json={})
        self.assertEqual(res_disc.status_code, 200)
        
        # Check status
        status_res = self.client.get("/api/bank/status")
        self.assertEqual(status_res.status_code, 200)
        conn = status_res.get_json()["connection"]
        self.assertEqual(conn["connection_status"], "DISCONNECTED")

        # Reconnect
        res_reconn = self.client.post("/api/bank/reconnect", json={})
        self.assertEqual(res_reconn.status_code, 200)
        
        status_res2 = self.client.get("/api/bank/status")
        conn2 = status_res2.get_json()["connection"]
        self.assertEqual(conn2["connection_status"], "CONNECTED")

    def test_13_bangladesh_mfs_connections(self):
        """Test Bangladesh MFS providers: bKash (bikash), Nagad (nogod), Rocket."""
        # 1. Test bKash with alias 'bikash'
        res_bkash = self.client.post("/api/bank/connect", json={
            "institution_id": "bikash",
            "account_type": "Personal Wallet"
        })
        self.assertEqual(res_bkash.status_code, 200)
        bkash_data = res_bkash.get_json()["connection"]
        self.assertEqual(bkash_data["institution_id"], "bkash")
        self.assertEqual(bkash_data["currency"], "BDT")
        self.assertTrue(bkash_data["masked_account_number"].startswith("+880 17"))

        # 2. Test Nagad with alias 'nogod'
        res_nagad = self.client.post("/api/bank/connect", json={
            "institution_id": "nogod",
            "account_type": "Personal Wallet"
        })
        self.assertEqual(res_nagad.status_code, 200)
        nagad_data = res_nagad.get_json()["connection"]
        self.assertEqual(nagad_data["institution_id"], "nagad")
        self.assertEqual(nagad_data["currency"], "BDT")
        self.assertTrue(nagad_data["masked_account_number"].startswith("+880 16"))

        # 3. Test Rocket
        res_rocket = self.client.post("/api/bank/connect", json={
            "institution_id": "rocket",
            "account_type": "Personal Wallet"
        })
        self.assertEqual(res_rocket.status_code, 200)
        rocket_data = res_rocket.get_json()["connection"]
        self.assertEqual(rocket_data["institution_id"], "rocket")
        self.assertEqual(rocket_data["currency"], "BDT")
        self.assertTrue(rocket_data["masked_account_number"].startswith("+880 19"))
        self.assertIn("-", rocket_data["masked_account_number"]) # Rocket check digit format

        # 4. Verify transaction feeds for Rocket have BDT currency and Tor fraud flag
        tx_res = self.client.get("/api/bank/transactions")
        self.assertEqual(tx_res.status_code, 200)
        tx_data = tx_res.get_json()
        self.assertTrue(tx_data["success"])
        self.assertEqual(tx_data["connection"]["currency"], "BDT")
        self.assertGreater(len(tx_data["transactions"]), 0)
        
        flagged_tx = next((t for t in tx_data["transactions"] if t["origin_ip"] == "185.220.101.5"), None)
        self.assertIsNotNone(flagged_tx)
        self.assertEqual(flagged_tx["fraud_status"], "FLAGGED")

if __name__ == "__main__":
    unittest.main(verbosity=2)
