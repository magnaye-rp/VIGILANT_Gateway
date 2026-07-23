# Vigilant AI Gateway Setup Guide (Ubuntu 24.04)
## Transparent AI Interception Gateway using dnsmasq, iptables, and mitmproxy

---

# Overview

This guide configures an Ubuntu Server to act as:

• Router (Gateway)  
• DHCP Server  
• DNS Forwarder  
• NAT device  
• Transparent MITM interception device  
• AI traffic analysis host  

Network architecture:

Internet ⇄ [enp0s5] Ubuntu Gateway [enp0s6] ⇄ Client VM

Gateway IP: 192.168.10.1

---

# Step 1 — Update System

```bash
sudo apt update && sudo apt upgrade -y
```

Ensures latest packages and security patches.

---

# Step 2 — Install Required Packages

```bash
sudo apt install -y python3-venv python3-pip iptables-persistent dnsmasq tcpdump curl isc-dhcp-client
```

---

# Step 3 — Create Project Directory

```bash
mkdir -p ~/vigilant
cd ~/vigilant
```

---

# Step 4 — Setup Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install mitmproxy spacy
python -m spacy download en_core_web_sm
```

---

# Step 5 — Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

Verify:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```
net.ipv4.ip_forward = 1
```

---

# Step 6 — Configure Network Interfaces

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:

    enp0s5:
      dhcp4: true

    enp0s6:
      addresses:
        - 192.168.10.1/24

      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
```

Apply:

```bash
sudo netplan apply
```

---

# Step 7 — Configure dnsmasq

```bash
sudo nano /etc/dnsmasq.conf
```

```conf
interface=enp0s6
bind-interfaces

dhcp-range=192.168.10.10,192.168.10.50,24h

dhcp-option=3,192.168.10.1

dhcp-option=6,192.168.10.1

server=8.8.8.8
server=1.1.1.1

no-resolv
```

Restart:

```bash
sudo systemctl restart dnsmasq
```

---

# Step 8 — Configure NAT

```bash
sudo iptables -t nat -F
sudo iptables -F

sudo iptables -t nat -A POSTROUTING -o enp0s5 -j MASQUERADE

sudo netfilter-persistent save
```

---

# Step 9 — Transparent Proxy Rules

```bash
sudo iptables -t nat -A PREROUTING -i enp0s6 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i enp0s6 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

---

# Step 10 — Disable Reverse Path Filtering

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.enp0s6.rp_filter=0
```

---

# Step 11 — Run mitmproxy

```bash
source ~/vigilant/venv/bin/activate

mitmdump --mode transparent --showhost -s brain_rot_filter.py
```

---

# Step 12 — Configure Client VM

```bash
sudo dhclient -r
sudo dhclient
```

Verify:

```bash
ip addr
```

Expected:

```
192.168.10.x
```

Verify DNS:

```bash
cat /etc/resolv.conf
```

Expected:

```
nameserver 192.168.10.1
```

---

# Step 13 — Testing

```bash
ping 192.168.10.1
ping 8.8.8.8
ping google.com
```

---

# Final Result

Client:

• gets IP automatically  
• connects to internet  
• traffic intercepted by gateway  
• AI analyzes traffic  

