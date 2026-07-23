import unittest
from unittest.mock import patch, MagicMock
import os
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import app

class TestGatewayFixes(unittest.TestCase):
    def setUp(self):
        # Reset the global logger failure flag before each test
        app._psutil_failed_logged = False

    def test_float_config_keys_coercion(self):
        """Verify network_velocity_threshold is parsed as float and not int."""
        # 1.5 should be successfully coerced under float config keys
        val = app._coerce_config_value("network_velocity_threshold", "1.5")
        self.assertEqual(val, 1.5)
        
        # 2.0 should also be coerced to float
        val = app._coerce_config_value("network_velocity_threshold", 2.0)
        self.assertEqual(val, 2.0)
        
        # Invalid floats should raise ValueError
        with self.assertRaises(ValueError):
            app._coerce_config_value("network_velocity_threshold", "invalid_float")

    def test_integer_config_keys_coercion(self):
        """Verify integer config keys like throttle_rate raise ValueError on float inputs."""
        with self.assertRaises(ValueError):
            app._coerce_config_value("throttle_rate", "1.5")
            
        val = app._coerce_config_value("throttle_rate", "256")
        self.assertEqual(val, 256)

    @patch("app.psutil")
    @patch("app.socket")
    def test_network_interfaces_fallback(self, mock_socket, mock_psutil):
        """Test consolidated get_system_interfaces function fallbacks."""
        # Scenario 1: socket works
        mock_socket.if_nameindex.return_value = [(1, "eth0"), (2, "eth1"), (3, "lo")]
        interfaces = app.get_system_interfaces()
        self.assertEqual(interfaces, ["eth0", "eth1"])
        
        # Scenario 2: socket raises exception, psutil works
        mock_socket.if_nameindex.side_effect = Exception("Socket failed")
        mock_psutil.net_if_addrs.return_value = {"enp0s3": None, "lo": None, "veth0": None}
        interfaces = app.get_system_interfaces()
        self.assertEqual(interfaces, ["enp0s3"])
        
        # Scenario 3: both socket and psutil fail, returns static fallback list
        mock_psutil.net_if_addrs.side_effect = Exception("Psutil failed")
        interfaces = app.get_system_interfaces()
        self.assertEqual(interfaces, ['eth0', 'eth1', 'enp0s3', 'enp1s0'])

    @patch.dict(os.environ, {
        "VIGILANT_PROXY_STATE": "active",
        "VIGILANT_DASHBOARD_STATE": "inactive",
        "VIGILANT_DNS_STATE": "offline"
    })
    @patch("app._systemctl_service_state")
    @patch("app._process_service_state")
    def test_service_state_environment_overrides(self, mock_proc, mock_sysctl):
        """Verify environment variable status overrides are respected."""
        # When VIGILANT_PROXY_STATE env var is set, it overrides the check
        proxy_state = app._get_service_state("proxy", "vigilant-proxy", "mitmdump")
        self.assertEqual(proxy_state, "active")
        
        # When VIGILANT_DASHBOARD_STATE env var is set, it overrides
        dash_state = app._get_service_state("dashboard", "vigilant-dashboard", "app.py")
        self.assertEqual(dash_state, "inactive")

        # When VIGILANT_DNS_STATE env var is set, it overrides dnsmasq
        dns_state = app._get_service_state("dnsmasq", "dnsmasq", "dnsmasq")
        self.assertEqual(dns_state, "offline")

    @patch("app.psutil")
    def test_process_service_state_resilience(self, mock_psutil):
        """Verify psutil process iteration exceptions are handled without spamming logs."""
        # Force psutil.process_iter to raise permission error / exception
        mock_psutil.process_iter.side_effect = PermissionError("Restricted environment")
        
        # Call process service state check
        with patch.object(app.app.logger, "debug") as mock_debug:
            state = app._process_service_state("mitmdump")
            self.assertEqual(state, "offline")
            
            # First failure should log a debug message
            mock_debug.assert_called_once()
            
            # Reset logger mock
            mock_debug.reset_mock()
            
            # Second failure should not log a debug message (debug-once mitigation)
            state = app._process_service_state("mitmdump")
            self.assertEqual(state, "offline")
            mock_debug.assert_not_called()
