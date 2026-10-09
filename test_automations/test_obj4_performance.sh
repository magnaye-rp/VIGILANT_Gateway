#!/bin/bash
# iPerf3 Performance Testing Script (Client Side)

# TODO: Replace with the actual IP address of the iPerf3 server running outside the gateway
SERVER_IP="192.168.1.100" 
DURATION=60

echo "============================================================"
echo " VIGILANT Performance Test - Objective 4 (Client Mode)"
echo "============================================================"
echo "Prerequisites:"
echo "1. Ensure 'iperf3' is installed on this Mac (brew install iperf3)"
echo "2. Ensure the iPerf3 server is running on $SERVER_IP (run: iperf3 -s)"
echo ""

# Check if iperf3 is installed
if ! command -v iperf3 &> /dev/null; then
    echo "Error: iperf3 is not installed. Please run 'brew install iperf3' and try again."
    exit 1
fi

echo "--- STEP 1: Baseline Test (VIGILANT FILTERING DISABLED) ---"
echo "Please disable the VIGILANT interception/filtering modules on the gateway."
read -p "Press Enter when VIGILANT filtering is DISABLED..."
echo "Running baseline test for $DURATION seconds..."
iperf3 -c $SERVER_IP -t $DURATION -J > baseline_result.json
echo "Baseline test complete."
echo ""

echo "--- STEP 2: Filtered Test (VIGILANT FILTERING ENABLED) ---"
echo "Please enable the VIGILANT interception/filtering modules on the gateway."
read -p "Press Enter when VIGILANT filtering is ENABLED..."
echo "Running filtered test for $DURATION seconds..."
iperf3 -c $SERVER_IP -t $DURATION -J > filtered_result.json
echo "Filtered test complete."
echo ""

echo "============================================================"
echo "Results saved to: "
echo " - baseline_result.json"
echo " - filtered_result.json"
echo ""
echo "Next Steps:"
echo "Extract the 'bits_per_second' from both JSON files."
echo "Calculate Throughput Efficiency = (Filtered Mbps / Baseline Mbps) * 100"
echo "Target Efficiency: >= 90%"
echo "============================================================"
