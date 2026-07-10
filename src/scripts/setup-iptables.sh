#!/bin/bash
set -e

# Use environment variables or fallback to defaults (for backward compatibility)
WAN_INTERFACE="${WAN_INTERFACE:-enp0s5}"
LAN_INTERFACE="${LAN_INTERFACE:-enp0s6}"
APPLE_CAPTIVE_PORTAL_NET="17.0.0.0/8"

echo "[1/7] Flushing existing rules..."
iptables -t nat -F && iptables -t mangle -F
iptables -F && iptables -X

echo "[2/7] Default policies..."
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "[3/7] NAT - internet sharing from LAN to WAN..."
iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

echo "[4/7] Transparent redirect - HTTP and HTTPS to mitmproxy..."
iptables -t nat -I PREROUTING 1 \
  -i "$LAN_INTERFACE" -d "$APPLE_CAPTIVE_PORTAL_NET" -p tcp --dport 80 -j ACCEPT
iptables -t nat -I PREROUTING 1 \
  -i "$LAN_INTERFACE" -d "$APPLE_CAPTIVE_PORTAL_NET" -p tcp --dport 443 -j ACCEPT
iptables -t nat -A PREROUTING \
  -i "$LAN_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING \
  -i "$LAN_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8080

echo "[5/7] Block QUIC - force TCP fallback..."
iptables -I FORWARD -i "$LAN_INTERFACE" -p udp --dport 443 -j DROP
iptables -I FORWARD -i "$LAN_INTERFACE" -p udp --dport 80  -j DROP

echo "[6/7] MSS clamping..."
iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --set-mss 1400

echo "[7/7] Allow established/related forwarding..."
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$LAN_INTERFACE" -j ACCEPT

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w "net.ipv4.conf.$LAN_INTERFACE.rp_filter=0"
sysctl -w "net.ipv4.conf.$WAN_INTERFACE.rp_filter=0"
sysctl -w net.ipv4.conf.default.rp_filter=0

grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || \
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
grep -qxF 'net.ipv4.conf.all.rp_filter=0' /etc/sysctl.conf || \
  echo 'net.ipv4.conf.all.rp_filter=0' >> /etc/sysctl.conf

netfilter-persistent save

echo "=== VERIFY: NAT table ==="
iptables -t nat -L PREROUTING -n -v
echo "=== VERIFY: FORWARD chain ==="
iptables -L FORWARD -n -v
