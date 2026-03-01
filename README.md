# V.I.G.I.L.A.N.T. 🛡️
**Versatile Infrastructure for Guided Inspection and Logical Analysis of Network Traffic**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20Server-orange)
![AI Model](https://img.shields.io/badge/AI-spaCy%20NLP-green)

---

## 📖 Overview
V.I.G.I.L.A.N.T. is a hardware-integrated security gateway designed for the **Lenovo ThinkCentre M710q**. It addresses the "Brain Rot" phenomenon by using **Deep Packet Inspection (DPI)** and **Natural Language Processing (NLP)** to analyze content metadata in real-time. Unlike traditional firewalls, V.I.G.I.L.A.N.T. scores the linguistic complexity of incoming traffic to protect user cognitive health.



---

## 🛠️ Hardware Specifications
* **Host:** Lenovo ThinkCentre M710q (x86 Tiny PC)
* **Storage:** 120Gb NVMe (Internal)
* **Network:** * **WAN:** Integrated Intel Gigabit Ethernet (Internet In)
    * **LAN:** Internal M.2 A+E Key Wi-Fi Card (Access Point Out)
* **OS:** Ubuntu Server 24.04 LTS (Headless)

---

## 🚀 Step-by-Step Installation Guide

### Phase 1: Hardware Setup
1. Open your Lenovo M710q and install a compatible **M.2 Wi-Fi card** (e.g., MediaTek or Atheros) into the A+E slot.
2. Ensure the antennas are properly connected for maximum range.
3. Plug in your **WAN Ethernet cable** to provide internet to the gateway.

### Phase 2: Software Installation
Run the following commands to transform your Ubuntu Server into the VIGILANT appliance:

```bash
# Clone the repository
git clone [https://github.com/magnaye-rp/VIGILANT_Gateway.git](https://github.com/magnaye-rp/VIGILANT_Gateway.git)
cd VIGILANT-Gateway

# Run the automated dependency installer
sudo bash scripts/install_deps.sh
