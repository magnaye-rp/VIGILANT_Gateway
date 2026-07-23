import unittest
import sqlite3
import os
import sys
import time
import tempfile
from pathlib import Path

# Add src folder to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import app
import vigilant_addon

class TestThrottlingAndLogSegregation(unittest.TestCase):
    def setUp(self):
        # Create a temporary database file
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_vigilant.db"
        
        # Point app and addon DB_PATH to temporary DB
        app.DB_PATH = self.db_path
        vigilant_addon.DB_PATH = str(self.db_path)
        
        # Configure app for testing
        app.app.config['TESTING'] = True
        self.client = app.app.test_client()
        
        # Initialize DB schemas
        app.init_db()
        vigilant_addon.init_db()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_throttle_events_schema_has_reason(self):
        with sqlite3.connect(self.db_path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(throttle_events)").fetchall()]
            self.assertIn("reason", columns)
            self.assertIn("rpm_current", columns)
            self.assertIn("rpm_baseline", columns)
            self.assertIn("action", columns)

    def test_log_throttle_insertion(self):
        vigilant_addon.log_throttle(
            client_ip="192.168.10.25",
            host="example.com",
            rpm_now=180.0,
            rpm_base=50.0,
            action="TLS_THROTTLE_APPLIED",
            reason="SNI/TLS velocity threshold exceeded"
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM throttle_events").fetchall()
            self.assertEqual(len(rows), 1)
            row = dict(rows[0])
            self.assertEqual(row["client_ip"], "192.168.10.25")
            self.assertEqual(row["host"], "example.com")
            self.assertEqual(row["action"], "TLS_THROTTLE_APPLIED")
            self.assertEqual(row["reason"], "SNI/TLS velocity threshold exceeded")

    def test_l7_traffic_log_segregation(self):
        # Insert L7 and L4 records into traffic_log
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), "192.168.10.10", "wiki.org", "/page", "GET", "Educational", 0)
            )
            conn.execute(
                "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), "192.168.10.10", "tracker.com", "(DNS_QUERY)", "DNS", "DNS_TRACKED", 0)
            )
            conn.execute(
                "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), "192.168.10.10", "passthrough.com", "(SNI_PASSTHROUGH)", "TLS", "SNI_PASSTHROUGH", 0)
            )
            conn.commit()

        # Call L7 traffic logs API
        res = self.client.get('/api/logs/traffic')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        logs = data["logs"]
        
        # Verify L7 endpoint excludes DNS_TRACKED and SNI_PASSTHROUGH
        categories = [log["category"] for log in logs]
        self.assertIn("Educational", categories)
        self.assertNotIn("DNS_TRACKED", categories)
        self.assertNotIn("SNI_PASSTHROUGH", categories)

    def test_throttling_logs_endpoint(self):
        # Insert throttle event and L4 tracking event
        vigilant_addon.log_throttle(
            client_ip="192.168.10.42",
            host="heavy-stream.com",
            rpm_now=200.0,
            rpm_base=30.0,
            action="DNS_THROTTLE_APPLIED",
            reason="DNS velocity threshold exceeded"
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), "192.168.10.42", "heavy-stream.com", "(DNS_QUERY)", "DNS", "DNS_TRACKED", 0)
            )
            conn.commit()

        res = self.client.get('/api/logs/throttling')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        logs = data["logs"]
        self.assertGreaterEqual(len(logs), 2)
        sources = [log["source"] for log in logs]
        self.assertIn("throttle_events", sources)
        self.assertIn("traffic_log", sources)

    def test_dynamic_throttled_devices_aggregation(self):
        # Log a dynamic throttle event
        vigilant_addon.log_throttle(
            client_ip="192.168.10.55",
            host="video-site.com",
            rpm_now=350.0,
            rpm_base=50.0,
            action="HTTP_THROTTLE_APPLIED",
            reason="HTTP velocity threshold exceeded"
        )

        res = self.client.get('/api/devices/throttled')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        throttled = data["throttled_devices"]
        self.assertEqual(len(throttled), 1)
        self.assertEqual(throttled[0]["client_ip"], "192.168.10.55")
        self.assertTrue(throttled[0]["is_throttled"])

    def test_csv_log_exporter_throttling_type(self):
        vigilant_addon.log_throttle(
            client_ip="192.168.10.88",
            host="test-export.com",
            rpm_now=120.0,
            rpm_base=20.0,
            action="TLS_THROTTLE_APPLIED",
            reason="SNI/TLS velocity threshold exceeded"
        )

        res = self.client.get('/api/logs/export?type=throttling')
        self.assertEqual(res.status_code, 200)
        self.assertIn('text/csv', res.headers['Content-Type'])
        csv_content = res.get_data(as_text=True)
        self.assertIn("192.168.10.88", csv_content)
        self.assertIn("TLS_THROTTLE_APPLIED", csv_content)

    def test_service_statuses_and_load_config(self):
        statuses = app._service_statuses()
        self.assertIn("mitmproxy", statuses)
        self.assertIn("dashboard", statuses)
        self.assertIn("dnsmasq", statuses)
        self.assertIn("firewall", statuses)

        cfg = app.load_config()
        self.assertIn("sni_filtering_enabled", cfg)
        self.assertIsInstance(cfg["sni_filtering_enabled"], bool)
        self.assertIn("throttle_enabled", cfg)
        self.assertIsInstance(cfg["throttle_enabled"], bool)

if __name__ == "__main__":
    unittest.main()
