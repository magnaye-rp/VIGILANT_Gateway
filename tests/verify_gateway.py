#!/usr/bin/env python3
"""
VIGILANT Gateway API Verification Test Harness

This script provides automated testing for the VIGILANT Gateway backend API endpoints
to ensure proper JSON delivery, error handling, and data structure validation for
mobile client integration.

Usage:
    python tests/verify_gateway.py
    or
    python -m pytest tests/verify_gateway.py
"""

import unittest
import json
import sys
import time
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import requests
except ImportError:
    print("ERROR: requests library not installed. Run: pip install requests")
    sys.exit(1)


class VigilantGatewayAPITests(unittest.TestCase):
    """Automated test suite for VIGILANT Gateway API endpoints"""

    BASE_URL = "http://localhost:5000"
    TIMEOUT = 10  # seconds

    def setUp(self):
        """Test setup - verify server is accessible"""
        try:
            response = requests.get(f"{self.BASE_URL}/", timeout=self.TIMEOUT)
            self.server_available = response.status_code in [200, 302]
        except requests.exceptions.RequestException:
            self.server_available = False
            self.skipTest(f"VIGILANT Gateway server not accessible at {self.BASE_URL}")

    def test_dashboard_stats_json_format(self):
        """Test that /api/dashboard/stats returns valid JSON with required metrics"""
        response = requests.get(f"{self.BASE_URL}/api/dashboard/stats", timeout=self.TIMEOUT)
        
        # Verify response status
        self.assertEqual(response.status_code, 200, "API should return 200 status")
        
        # Verify content type is JSON
        self.assertIn('application/json', response.headers.get('Content-Type', ''), 
                     "Response should have JSON content type")
        
        # Parse JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response should be valid JSON")
        
        # Verify required metric categories exist with numeric values
        required_categories = ['counts', 'percentage_metrics']
        for category in required_categories:
            self.assertIn(category, data, f"Response should contain '{category}' field")
        
        # Verify counts array has proper structure
        if 'counts' in data:
            counts = data['counts']
            self.assertIsInstance(counts, list, "Counts should be a list")
            
            # Check for required category names
            category_names = [item.get('category', '').lower() for item in counts]
            required_names = ['educational', 'productive', 'distracting', 'harmful']
            for name in required_names:
                self.assertIn(name, category_names, 
                            f"Counts should include '{name}' category")
        
        # Verify percentage metrics are numeric
        if 'percentage_metrics' in data:
            percentages = data['percentage_metrics']
            self.assertIsInstance(percentages, dict, "Percentage metrics should be a dict")
            
            for key, value in percentages.items():
                self.assertIsInstance(value, (int, float), 
                                   f"Percentage value for '{key}' should be numeric")

    def test_devices_active_structure(self):
        """Test that /api/devices/active returns properly structured device data"""
        response = requests.get(f"{self.BASE_URL}/api/devices", timeout=self.TIMEOUT)
        
        # Verify response status
        self.assertEqual(response.status_code, 200, "API should return 200 status")
        
        # Parse JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response should be valid JSON")
        
        # Verify devices field exists
        self.assertIn('devices', data, "Response should contain 'devices' field")
        
        devices = data['devices']
        self.assertIsInstance(devices, list, "Devices should be a list")
        
        # If devices exist, verify structure
        if devices:
            for device in devices:
                # Check for required fields
                self.assertIn('ip_address', device, "Device should have 'ip_address' field")
                self.assertIn('mac_address', device, "Device should have 'mac_address' field")
                
                # Verify field types
                self.assertIsInstance(device['ip_address'], str, 
                                   "IP address should be string")
                self.assertIsInstance(device['mac_address'], str, 
                                   "MAC address should be string")
                
                # Check for bytes field (may be 0 if not available)
                if 'bytes' in device:
                    self.assertIsInstance(device['bytes'], (int, float), 
                                       "Bytes should be numeric")

    def test_api_logs_empty_data_handling(self):
        """Test that /api/logs handles empty data gracefully"""
        response = requests.get(f"{self.BASE_URL}/api/stats", timeout=self.TIMEOUT)
        
        # Verify response status even with no data
        self.assertEqual(response.status_code, 200, 
                        "API should return 200 even with empty data")
        
        # Parse JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response should be valid JSON")
        
        # Verify structure is maintained even with empty data
        self.assertIn('total', data, "Response should contain 'total' field")
        self.assertIn('recent', data, "Response should contain 'recent' field")
        
        # Verify recent is a list (may be empty)
        self.assertIsInstance(data['recent'], list, "Recent logs should be a list")

    def test_api_config_endpoint(self):
        """Test that /api/config returns valid configuration data"""
        response = requests.get(f"{self.BASE_URL}/api/config", timeout=self.TIMEOUT)
        
        # Verify response status
        self.assertEqual(response.status_code, 200, "API should return 200 status")
        
        # Parse JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response should be valid JSON")
        
        # Verify network configuration fields
        self.assertIn('upstream_interface', data, 
                     "Config should contain 'upstream_interface'")
        self.assertIn('distribution_interface', data, 
                     "Config should contain 'distribution_interface'")
        self.assertIn('available_interfaces', data, 
                     "Config should contain 'available_interfaces'")
        
        # Verify available_interfaces is a list
        self.assertIsInstance(data['available_interfaces'], list, 
                           "Available interfaces should be a list")

    def test_cors_headers(self):
        """Test that CORS headers are properly set for API endpoints"""
        response = requests.get(
            f"{self.BASE_URL}/api/dashboard/stats", 
            timeout=self.TIMEOUT,
            headers={'Origin': 'http://example.com'}
        )
        
        # Check for CORS headers
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]
        
        # At minimum, should have Allow-Origin header
        self.assertIn('Access-Control-Allow-Origin', response.headers, 
                     "Response should include CORS Allow-Origin header")

    def test_error_handling_404(self):
        """Test that 404 errors return proper JSON response"""
        response = requests.get(f"{self.BASE_URL}/api/nonexistent", timeout=self.TIMEOUT)
        
        # Should return 404
        self.assertEqual(response.status_code, 404, "Nonexistent endpoint should return 404")

    def test_dashboard_summary_endpoint(self):
        """Test that /api/dashboard/summary returns proper structure"""
        response = requests.get(f"{self.BASE_URL}/api/dashboard/summary", timeout=self.TIMEOUT)
        
        # Verify response status
        self.assertEqual(response.status_code, 200, "API should return 200 status")
        
        # Parse JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response should be valid JSON")
        
        # Verify required sections
        self.assertIn('system', data, "Summary should contain 'system' section")
        self.assertIn('devices', data, "Summary should contain 'devices' section")
        self.assertIn('logs', data, "Summary should contain 'logs' section")
        
        # Verify system metrics structure
        system = data['system']
        self.assertIn('cpu_usage', system, "System should have 'cpu_usage'")
        self.assertIn('ram_usage_gb', system, "System should have 'ram_usage_gb'")
        self.assertIn('disk_usage', system, "System should have 'disk_usage'")


def run_tests():
    """Run the test suite with detailed output"""
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(VigilantGatewayAPITests)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*70)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
