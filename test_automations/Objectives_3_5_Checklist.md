# Manual Testing Checklist: Objectives 3 & 5

Since Objectives 3 and 5 require manual observation, physical devices, and gateway-side monitoring, use this checklist and the provided terminal commands to execute the tests and measure success.

## Objective 3: Behavioral Throttling Module
**Goal:** Verify doomscrolling session escalation and idle reset.

### 📋 Test Checklist
- [ ] **Start Engagement:** Connect a device and start continuously scrolling/streaming on a social media platform (e.g., TikTok, Instagram Reels).
- [ ] **0 to 3 Minutes (Unthrottled):** Verify the device's internet speed is normal.
- [ ] **Minute 3 (Level 1):** Verify the device's bandwidth is severely degraded (capped at ~128 kbit). Videos should start buffering heavily.
- [ ] **Minute 6 (Level 2):** Verify bandwidth is capped at ~32 kbit. Images may fail to load.
- [ ] **Minute 12 (Level 3):** Verify bandwidth is capped at ~4 kbit. The application should essentially time out or fail to refresh.
- [ ] **Idle Reset:** Close the app and stop all traffic from the device. Start a stopwatch for exactly **180 seconds**.
- [ ] **Post-Reset Check:** At 181 seconds, open the app again. Verify that bandwidth is completely restored to normal (unthrottled).

### 🖥️ Gateway Monitoring Commands (Run these via SSH on the VIGILANT Gateway)
To actively monitor the throttling queues and bandwidth caps being applied to the client IP:

1. **Monitor live bandwidth usage by IP (using `iftop`):**
   ```bash
   sudo iftop -i eth0  # Replace eth0 with your LAN interface
   ```
2. **Monitor Traffic Control (tc) Queuing Disciplines (to verify the 128k/32k/4k caps):**
   ```bash
   # Show current tc qdiscs and classes for the interface
   sudo tc -s qdisc show dev eth0
   sudo tc -s class show dev eth0
   ```
3. **Watch the tc rules update in real-time:**
   ```bash
   watch -n 1 'sudo tc -s class show dev eth0'
   ```

---

## Objective 5: 30-Device Stress Testing
**Goal:** Ensure the gateway maintains uninterrupted operation and stable resources with 30 concurrent connected devices.

### 📋 Test Checklist
- [ ] **Connect Devices:** Successfully connect all 30 real devices to the VIGILANT network.
- [ ] **Generate Load:** Ensure all devices are actively generating varied traffic (streaming, browsing, social media) simultaneously.
- [ ] **Duration:** Maintain this load for a sustained period (e.g., 1 to 2 hours).
- [ ] **Stability Check 1 (No Crashes):** Verify the gateway OS does not crash, reboot, or drop the network interface.
- [ ] **Stability Check 2 (Pipeline Check):** Verify the Categorization Pipeline is still processing and classifying logs.
- [ ] **Stability Check 3 (Throttling Check):** Randomly select a device that has been doomscrolling for >3 minutes and verify it is successfully throttled, while a freshly connected device is not.

### 🖥️ Gateway Monitoring Commands (Run these via SSH on the VIGILANT Gateway)
To ensure the system is stable and not facing resource exhaustion under the 30-device load:

1. **Monitor System Resources (CPU & RAM):**
   ```bash
   htop
   # Note: Look at the memory usage bar to ensure it's not maxing out the 8 GB RAM, and check CPU load averages.
   ```
2. **Monitor System Logs (for crashes or OOM errors):**
   ```bash
   # Follow the tail of system logs
   tail -f /var/log/syslog
   
   # Check specifically for Out Of Memory (OOM) killer events
   dmesg -T | grep -i oom
   ```
3. **Monitor Active Connections (to ensure devices aren't being dropped):**
   ```bash
   # Count the number of active TCP connections
   netstat -ant | grep ESTABLISHED | wc -l
   ```
