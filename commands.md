Vigilant Gateway — SSH Monitoring Commands

### 🔍 Proxy & Service Monitoring

| # | Command | What It Does |
|---|---|---|
| 1 | `sudo journalctl -u vigilant-proxy -f --output=cat` | Live tail of mitmproxy addon output — shows all SNI logging, bypass decisions, throttle events |
| 2 | `sudo journalctl -u vigilant-proxy.service -f -n 100` | Same as above but starts with the last 100 lines of history before live-tailing |
| 3 | `sudo journalctl -u vigilant-proxy --since "5 min ago" --output=cat` | Dump the last 5 minutes of proxy logs (non-following, good for spot checks) |
| 4 | `sudo journalctl -u vigilant-dashboard -f --output=cat` | Live tail of the Flask dashboard (startup, API errors, config reloads) |
| 5 | `sudo systemctl status vigilant-proxy vigilant-dashboard` | Quick health check — are both services running? |

### 🔬 Engagement & Throttle Filtering

| # | Command | What It Does |
|---|---|---|
| 6 | `sudo journalctl -u vigilant-proxy -f --output=cat \| grep -E "ENGAGEMENT\|Engaged\|release"` | Watch for doomscroll engagement level changes and throttle releases in real time |
| 7 | `sudo journalctl -u vigilant-proxy -f --output=cat \| grep -E "THROTTLE\|CB Level\|circuit"` | Watch circuit breaker escalations (L1 Pause → L2 Friction → L3 Circuit Break) |
| 8 | `sudo journalctl -u vigilant-proxy -f --output=cat \| grep -E "SSL Pinning\|pending_bypass\|Bypass"` | Track SSL pinning detections and bypass decisions |
| 9 | `sudo journalctl -u vigilant-proxy --since "1 hour ago" --output=cat \| grep -c "CB Level"` | Count how many circuit breaker events fired in the last hour |

### 📊 Database Inspection

| # | Command | What It Does |
|---|---|---|
| 10 | `watch -n 10 'echo "=== THROTTLED ===" && python3 -c "import sqlite3; conn = sqlite3.connect(\"/home/vigilant-admin/vigilant_gateway/logs/vigilant.db\"); rows = conn.execute(\"SELECT client_ip,is_throttled FROM throttle_state WHERE is_throttled=1\").fetchall(); [print(f\"  {r[0]}  throttled={r[1]}\") for r in rows] if rows else print(\"  (none)\"); conn.close()"' && echo "=== TC ===" && tc -s class show dev enp1s0 \| grep -E "rate\|Sent\|dropped"` | Every 10s: show throttled clients from the database + kernel `tc` byte counters on `enp1s0` |
| 11 | `watch -n 15 'python3 -c "import sqlite3; conn = sqlite3.connect(\"/home/vigilant-admin/vigilant_gateway/logs/vigilant.db\"); rows = conn.execute(\"SELECT domain, client_ip, occurrence_count, last_seen FROM pending_bypass_review ORDER BY last_seen DESC LIMIT 10\").fetchall(); [print(f\"{r[0]:40s} {r[1]:16s} x{r[2]:<4d} {r[3]}\") for r in rows] if rows else print(\"(none)\"); conn.close()"` | Every 15s: top 10 pending SSL pinning bypasses awaiting admin review |
| 12 | `python3 -c "import sqlite3,time; conn=sqlite3.connect('/home/vigilant-admin/vigilant_gateway/logs/vigilant.db'); rows=conn.execute('SELECT category,COUNT(*) FROM traffic_log WHERE timestamp > ? GROUP BY category',(time.time()-3600,)).fetchall(); [print(f'{r[0]:15s} {r[1]}') for r in rows]; conn.close()"` | One-shot: traffic category breakdown for the last hour |

### 🧱 Kernel Traffic Control (`tc`) Inspection

| # | Command | What It Does |
|---|---|---|
| 13 | `tc -s qdisc show dev enp1s0` | Show root qdisc + per-class byte/packet/drop counters for all throttled devices |
| 14 | `tc -s class show dev enp1s0 \| grep -B1 -E "rate\|Sent\|dropped"` | Condensed view: rate limit + bytes sent + drops per class (one class per throttled client) |
| 15 | `tc filter show dev enp1s0` | List all `u32` filters (one src + one dst filter per throttled client IP) |
| 16 | `for cls in $(tc class show dev enp1s0 \| grep -oP 'class htb 1:\K[0-9a-f]+'); do echo "--- classid 1:$cls ---"; tc -s class show dev enp1s0 classid 1:$cls \| grep -E 'rate|Sent|dropped'; done` | Loop over every class on the interface and show rate + stats |

### 🌐 Interface & Traffic

| # | Command | What It Does |
|---|---|---|
| 17 | `sudo ss -tunp \| grep -E ":8080\|:8081"` | Show processes listening on mitmproxy (8080) and dashboard (8081) |
| 18 | `sudo ss -tunp \| grep -E ":8080" \| wc -l` | Count current active TCP connections through the proxy |
| 19 | `watch -n 2 'cat /proc/net/dev \| grep -E "enp1s0\|enp2s0\|eth"'` | Every 2s: real-time RX/TX byte counters for all Ethernet interfaces |
| 20 | `ip -s link show enp1s0` | Detailed interface stats — packets, bytes, errors, drops, overruns |

### 📡 LAN & DHCP

| # | Command | What It Does |
|---|---|---|
| 21 | `cat /var/lib/misc/dnsmasq.leases` | Show all DHCP leases — MAC → IP → hostname mappings for every LAN device |
| 22 | `watch -n 30 'cat /var/lib/misc/dnsmasq.leases'` | Refresh DHCP lease list every 30s to catch new devices joining |
| 23 | `arp -a` | Show the kernel's ARP cache — all recently active LAN IPs and their MAC addresses |
| 24 | `nmap -sn 172.20.10.0/24` | Quick LAN ping sweep to discover all online devices (requires `nmap`) |

### 🧹 Reset & Recovery (⚠️ USE WITH CAUTION)

| # | Command | What It Does |
|---|---|---|
| 25 | `sudo tc qdisc del dev enp1s0 root && sudo tc qdisc add dev enp1s0 root handle 1: htb default 1` | **Hard reset**: tears down all tc throttles on `enp1s0` and recreates a clean root qdisc. Drops ALL existing class/filter rules. Use when throttles are stuck or misconfigured. |
| 26 | `sudo tc qdisc replace dev enp1s0 root handle 1: htb default 1` | **Soft reset** (preferred): atomically replaces the root qdisc — same effect as above but without the brief gap where no qdisc exists. Safer to use than the `del`+`add` pair. |
| 27 | `sudo systemctl restart vigilant-proxy` | Restart the mitmproxy addon — restores throttle states from the database on startup |

### 📝 Logs (Filesystem)

| # | Command | What It Does |
|---|---|---|
| 28 | `tail -f /var/log/syslog \| grep -i vigilant` | Live system-level log entries mentioning Vigilant |
| 29 | `ls -lh /home/vigilant-admin/vigilant_gateway/logs/` | Check log directory — `vigilant.db` size, `.rule_cache_reload` and `.throttle_release_queue` IPC files |
| 30 | `journalctl --disk-usage` | Check how much disk space journald logs are consuming |

---

### Quick-Copy Cheat Sheet

```bash
# Health check
sudo systemctl status vigilant-proxy vigilant-dashboard

# Live proxy tail
sudo journalctl -u vigilant-proxy -f --output=cat

# Engagement + throttle filtering
sudo journalctl -u vigilant-proxy -f --output=cat | grep -E "ENGAGEMENT|CB Level|release"

# Throttle DB + tc snapshot (10s refresh)
watch -n 10 'echo "=== THROTTLED ===" && python3 -c "
import sqlite3
conn = sqlite3.connect(\"/home/vigilant-admin/vigilant_gateway/logs/vigilant.db\")
rows = conn.execute(\"SELECT client_ip,is_throttled FROM throttle_state WHERE is_throttled=1\").fetchall()
for r in rows: print(f\"  {r[0]}  throttled={r[1]}\")
if not rows: print(\"  (none)\")
conn.close()
" && echo "=== TC ===" && tc -s class show dev enp1s0 | grep -E "rate|Sent|dropped"'

# Soft reset all throttles (safe)
sudo tc qdisc replace dev enp1s0 root handle 1: htb default 1

# DHCP + ARP
cat /var/lib/misc/dnsmasq.leases && arp -a
