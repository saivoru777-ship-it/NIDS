# NIDS Testing Guide for Nutanix Environment

## VM Setup Requirements

### Minimum Setup (3 VMs)

#### VM 1: NIDS Monitor (Ubuntu/Debian)
**Purpose**: Run the NIDS to monitor network traffic

**Specifications**:
- **OS**: Ubuntu 22.04 LTS or Debian 12
- **vCPUs**: 2
- **RAM**: 4 GB
- **Disk**: 20 GB
- **Network**: 1 NIC in promiscuous mode
- **Software**: Python 3.8+, NIDS installed

**Setup**:
```bash
# Install Python and dependencies
sudo apt update
sudo apt install python3 python3-pip git -y

# Clone/copy NIDS to this VM
# Install requirements
cd NIDS
pip3 install -r requirements.txt
```

#### VM 2: Target/Victim Machine (Ubuntu Server)
**Purpose**: Target for attack simulations

**Specifications**:
- **OS**: Ubuntu 22.04 Server
- **vCPUs**: 2
- **RAM**: 2 GB
- **Disk**: 20 GB
- **Network**: 1 NIC (same network as NIDS)
- **Services**: SSH, HTTP, FTP (optional)

**Setup**:
```bash
# Install services to test against
sudo apt update
sudo apt install openssh-server apache2 vsftpd -y

# Verify services running
sudo systemctl status ssh
sudo systemctl status apache2
```

#### VM 3: Attacker Machine (Kali Linux)
**Purpose**: Generate attack traffic for testing

**Specifications**:
- **OS**: Kali Linux 2024.x
- **vCPUs**: 2
- **RAM**: 4 GB
- **Disk**: 30 GB
- **Network**: 1 NIC (same network)
- **Tools**: Pre-installed security tools (nmap, hping3, etc.)

**Why Kali?**: Comes with all penetration testing tools pre-installed

---

## Network Configuration

### Option 1: Shared Network Segment (Easier)
All VMs on the same network (e.g., 192.168.100.0/24)

```
┌─────────────────┐
│  NIDS Monitor   │  192.168.100.10
│  (Ubuntu)       │  - Promiscuous mode enabled
└────────┬────────┘  - Captures all traffic
         │
         │
    ┌────┴─────────────────┐
    │   Network Switch     │
    │   192.168.100.0/24   │
    └────┬──────────┬──────┘
         │          │
         │          │
┌────────┴────┐  ┌──┴───────────┐
│   Target    │  │   Attacker   │
│  (Ubuntu)   │  │  (Kali)      │
│ .100.20     │  │  .100.30     │
└─────────────┘  └──────────────┘
```

**Nutanix Configuration**:
1. Create a Virtual Network (VLAN)
2. Enable promiscuous mode on NIDS VM's NIC
3. Assign all VMs to same network

### Option 2: SPAN/Mirror Port (Advanced)
Configure Nutanix network to mirror traffic to NIDS VM

---

## Step-by-Step Testing Procedures

### Phase 1: Initial Setup & Baseline

#### On NIDS VM (192.168.100.10):

```bash
# 1. Find your network interface
sudo python3 main.py --list-interfaces
# Example output: eth0, ens3, etc.

# 2. Update config with your interface
nano config/config.yaml
# Change: interface: "eth0"  (use your interface name)

# 3. Start NIDS
sudo python3 main.py -i eth0

# 4. Wait 5 minutes for baseline collection
# During this time, generate NORMAL traffic (see below)
```

#### On Target VM (192.168.100.20):

```bash
# Keep services running
# Browse a few websites to generate normal traffic
curl http://google.com
curl http://example.com

# SSH to localhost a few times
ssh localhost
```

#### On Attacker VM (192.168.100.30):

```bash
# During baseline: Generate NORMAL traffic only
ping -c 10 192.168.100.20
curl http://192.168.100.20
```

**Expected Result**: No alerts during baseline, just statistics collection

---

### Phase 2: Attack Testing

After baseline is established (5 minutes), run these tests:

---

### Test 1: Port Scan Detection

#### On Attacker VM:

```bash
# Basic port scan
nmap 192.168.100.20

# More aggressive scan (faster detection)
nmap -p 1-100 192.168.100.20

# Even more ports
nmap -p 1-1000 192.168.100.20

# Stealth SYN scan
sudo nmap -sS -p 1-50 192.168.100.20
```

#### Expected Alert on NIDS:

```
================================================================================
ALERT #X - HIGH SEVERITY
================================================================================
Type: port_scan
Description: Port scan detected: 25 unique ports scanned
Source IP: 192.168.100.30
Destination IP: 192.168.100.20
Details:
  port_count: 25
  time_window: 45.2
================================================================================
```

---

### Test 2: SYN Flood Attack

#### On Attacker VM:

```bash
# Install hping3 if not available
sudo apt install hping3 -y

# SYN flood attack (10 seconds)
sudo hping3 -S --flood -p 80 192.168.100.20 -c 200

# Or specific rate
sudo hping3 -S -p 80 --faster 192.168.100.20 -c 200
```

#### Expected Alert on NIDS:

```
================================================================================
ALERT #X - CRITICAL SEVERITY
================================================================================
Type: syn_flood
Description: SYN flood detected: 150 SYN packets
Source IP: 192.168.100.30
Destination IP: 192.168.100.20
Details:
  syn_count: 150
  ack_count: 5
  time_window: 8.5
================================================================================
```

---

### Test 3: ICMP Flood (Ping Flood)

#### On Attacker VM:

```bash
# ICMP flood
sudo hping3 --icmp --flood 192.168.100.20 -c 100

# Or use ping with fast interval
sudo ping -f 192.168.100.20
# Press Ctrl+C after 5 seconds
```

#### Expected Alert on NIDS:

```
================================================================================
ALERT #X - HIGH SEVERITY
================================================================================
Type: icmp_flood
Description: ICMP flood detected: 75 packets
Source IP: 192.168.100.30
Destination IP: 192.168.100.20
Details:
  packet_count: 75
  time_window: 4.2
================================================================================
```

---

### Test 4: SSH Brute Force (Simulated)

#### On Attacker VM:

```bash
# Multiple failed SSH attempts
for i in {1..10}; do
  ssh baduser@192.168.100.20
  sleep 2
done

# Or use hydra (pre-installed on Kali)
hydra -l root -P /usr/share/wordlists/rockyou.txt.gz 192.168.100.20 ssh -t 4 -V
```

#### Expected Alert:
Should trigger signature match for SSH brute force

---

### Test 5: Web Attack Simulation

#### On Attacker VM:

```bash
# SQL Injection attempt
curl "http://192.168.100.20/index.php?id=1' OR '1'='1"

# XSS attempt
curl "http://192.168.100.20/search?q=<script>alert('xss')</script>"

# Multiple attempts
curl "http://192.168.100.20/login?user=admin&pass=' OR 1=1--"
```

#### Expected Alert:
Signature match for SQL injection or XSS patterns

---

### Test 6: Traffic Volume Anomaly

#### On Attacker VM:

```bash
# Generate high traffic volume
# Download large file repeatedly
for i in {1..50}; do
  curl -O http://192.168.100.20/largefile.iso &
done

# Or use iperf for bandwidth testing
# On Target: iperf -s
# On Attacker: iperf -c 192.168.100.20 -t 60
```

#### Expected Alert:

```
================================================================================
ALERT #X - MEDIUM SEVERITY
================================================================================
Type: traffic_volume_anomaly
Description: Traffic volume anomaly: 250 packets (baseline: 45 ± 10)
Details:
  current_volume: 250
  baseline_mean: 45.0
  deviation: 20.5
================================================================================
```

---

### Test 7: Unusual Port Usage

#### On Attacker VM:

```bash
# Access uncommon ports
nc 192.168.100.20 4444
nc 192.168.100.20 31337
nc 192.168.100.20 6666

# Telnet to unusual ports
telnet 192.168.100.20 8888
```

#### Expected Alert:
Unusual port usage detection (if these weren't in baseline)

---

### Test 8: ARP Spoofing (Advanced)

#### On Attacker VM:

```bash
# Install arpspoof
sudo apt install dsniff -y

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# ARP spoofing
sudo arpspoof -i eth0 -t 192.168.100.20 192.168.100.1
```

#### Expected Alert:

```
================================================================================
ALERT #X - CRITICAL SEVERITY
================================================================================
Type: arp_spoofing
Description: ARP spoofing detected: IP address with different MAC
Details:
  old_mac: aa:bb:cc:dd:ee:ff
  new_mac: 11:22:33:44:55:66
================================================================================
```

---

## Testing Checklist

### Pre-Test Setup
- [ ] All 3 VMs created and running
- [ ] Network configured (same subnet)
- [ ] NIDS VM has promiscuous mode enabled
- [ ] NIDS installed and dependencies met
- [ ] Target VM has services running (SSH, HTTP)
- [ ] Attacker VM has tools installed (Kali preferred)

### Baseline Collection (5 minutes)
- [ ] NIDS started successfully
- [ ] Normal traffic generated
- [ ] Baseline established message appears
- [ ] No false positive alerts

### Attack Tests
- [ ] Test 1: Port Scan (nmap)
- [ ] Test 2: SYN Flood (hping3)
- [ ] Test 3: ICMP Flood (ping flood)
- [ ] Test 4: SSH Brute Force
- [ ] Test 5: Web Attacks (SQL injection/XSS)
- [ ] Test 6: Traffic Volume Anomaly
- [ ] Test 7: Unusual Port Access
- [ ] Test 8: ARP Spoofing (optional)

### Verification
- [ ] Alerts displayed in console
- [ ] Alerts logged to files
- [ ] Alert severity levels correct
- [ ] Statistics displayed correctly
- [ ] Final summary generated on exit

---

## Nutanix-Specific Configuration

### Enable Promiscuous Mode on NIDS VM

**Via Nutanix Prism**:
1. Select NIDS VM
2. Go to Network Adapters
3. Edit NIC settings
4. Enable "Promiscuous Mode" or "Monitor Mode"
5. Save and update VM

**Via CLI (on NIDS VM after boot)**:
```bash
# Check interface
ip link show

# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Verify
ip link show eth0 | grep PROMISC
```

### Create Virtual Network

**In Nutanix Prism**:
1. Go to Network Configuration
2. Create new Virtual Network
3. Name: "NIDS-Test-Network"
4. VLAN ID: 100 (or your choice)
5. Subnet: 192.168.100.0/24
6. DHCP: Optional (or use static IPs)

### Assign VMs to Network

For each VM:
1. VM Settings → Network Adapters
2. Connect to "NIDS-Test-Network"
3. Save

---

## Alternative: Simplified 2-VM Setup

If resources are limited:

### VM 1: NIDS + Target (Ubuntu)
- Run NIDS
- Also host services to attack
- IP: 192.168.100.10

### VM 2: Attacker (Kali)
- Run attacks against VM 1
- IP: 192.168.100.20

**Note**: Less realistic but functional for basic testing

---

## Monitoring & Verification

### On NIDS VM

**Monitor console output**:
```bash
sudo python3 main.py -i eth0
```

**In another terminal, tail logs**:
```bash
# Watch logs in real-time
tail -f logs/nids_alerts_*.json

# Pretty print JSON logs
tail -f logs/nids_alerts_*.json | jq '.'

# Count alerts
cat logs/nids_alerts_*.json | wc -l
```

### View Statistics

Traffic statistics print every 60 seconds:
- Total packets captured
- Protocol distribution
- Top source IPs (attacker should appear)
- Top destination IPs (target should appear)
- Most accessed ports

---

## Expected Timeline

```
00:00 - Start NIDS
00:01 - Generate normal traffic
00:05 - Baseline established
00:06 - Start Test 1: Port Scan → Alert within 60s
00:08 - Start Test 2: SYN Flood → Alert within 10s
00:10 - Start Test 3: ICMP Flood → Alert within 5s
00:12 - Start Test 4: Brute Force → Alert varies
00:15 - Start Test 5: Web Attacks → Immediate alerts
00:18 - Start Test 6: Traffic Anomaly → Alert within 60s
00:20 - Review all alerts and logs
00:22 - Stop NIDS (Ctrl+C), view final summary
```

**Total Testing Time**: ~25-30 minutes

---

## Troubleshooting

### No Alerts Appearing

**Check**:
- Promiscuous mode enabled?
- All VMs on same network?
- NIDS listening on correct interface?
- Baseline completed (5 min)?
- Firewall blocking traffic?

```bash
# Verify NIDS is capturing packets
sudo tcpdump -i eth0 -c 10

# Check if interface is in promisc mode
ip link show eth0 | grep PROMISC
```

### Too Many False Positives

**Adjust thresholds** in `config/config.yaml`:
```yaml
port_scan:
  threshold: 30  # Increase from 20
  time_window: 90  # Increase from 60

syn_flood:
  threshold: 200  # Increase from 100
```

### Can't Ping Between VMs

**Check**:
```bash
# On each VM, check firewall
sudo ufw status

# Disable for testing (re-enable after)
sudo ufw disable

# Test connectivity
ping 192.168.100.20
```

### Permission Errors

```bash
# Ensure running with sudo
sudo python3 main.py

# Check file permissions
ls -la main.py
chmod +x main.py
```

---

## Demo Script (For Presentation)

```bash
# Terminal 1: NIDS Monitor
sudo python3 main.py -i eth0

# Wait 5 minutes, then in Terminal 2:
# Show baseline established

# Terminal 3: Attacker VM
# Demo 1: Port scan
nmap -p 1-100 192.168.100.20
# Switch to Terminal 1, show alert

# Demo 2: SYN flood
sudo hping3 -S --flood -p 80 192.168.100.20 -c 200
# Show critical alert

# Demo 3: Web attack
curl "http://192.168.100.20/?id=1' OR '1'='1"
# Show signature match alert

# Exit NIDS (Ctrl+C)
# Show final statistics and alert summary

# Show log file
cat logs/nids_alerts_*.json | jq '.'
```

---

## Clean Up After Testing

```bash
# Stop NIDS (Ctrl+C)

# Stop attack tools
sudo killall hping3 nmap

# Archive logs
tar -czf nids_test_logs_$(date +%Y%m%d).tar.gz logs/

# Reset baseline (optional)
rm -f nids_state.json

# Re-enable firewalls if disabled
sudo ufw enable
```

---

## Summary

**Minimum Requirements**:
- 3 VMs (Monitor, Target, Attacker)
- Same network segment
- Promiscuous mode on NIDS VM
- 5 minutes baseline + 20 minutes testing

**Expected Results**:
- 8+ different types of alerts
- Real-time detection (seconds to minutes)
- Comprehensive logs
- Traffic statistics

**Success Criteria**:
- ✅ Port scans detected
- ✅ Flood attacks detected
- ✅ Anomalous traffic identified
- ✅ Alerts logged correctly
- ✅ No false negatives on obvious attacks

Good luck with your testing! 🚀
