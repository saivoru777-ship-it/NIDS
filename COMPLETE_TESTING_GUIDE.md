# Complete NIDS Testing Guide - Start to Finish

**Timeline**: 60-90 minutes total
**Goal**: Fully test your NIDS with real attacks and get results

---

## 📋 Phase 1: VM Setup in Nutanix (30 minutes)

### Step 1.1: Create NIDS Monitor VM

**In Nutanix Prism:**
1. Click "Create VM"
2. Fill in:
   ```
   Name: NIDS-Monitor
   Description: Network Intrusion Detection System
   Project: CNIT471G007
   Cluster: virtual-lab-cluster

   vCPUs: 2
   Cores per vCPU: 2
   Memory: 4 GiB

   Disk: + Add New Disk
     - Type: Disk
     - Operation: Clone from Image
     - Image: Ubuntu-22.04-server (select from list)
     - Size: 20 GiB

   Network: + Add New NIC
     - VLAN: Select your network (or create NIDS-Test-Network)
   ```

3. Click "Save"
4. **CRITICAL**: After VM is created:
   - Select VM → Actions → Update
   - Network Adapters → Click on NIC
   - ✅ **Enable "Promiscuous Mode"** or "MAC Spoofing"
   - Save

### Step 1.2: Create Target Server VM

Same process, but:
```
Name: Target-Server
vCPUs: 2
Cores per vCPU: 1
Memory: 2 GiB
Disk: 20 GiB (Ubuntu 22.04)
Network: Same network as NIDS-Monitor
```

### Step 1.3: Create Attacker VM

Same process, but:
```
Name: Attacker-Kali
vCPUs: 2
Cores per vCPU: 2
Memory: 4 GiB
Disk: 30 GiB (Kali Linux - download ISO first)
Network: Same network as others
```

**Kali ISO**: Download from https://www.kali.org/get-kali/#kali-installer-images
- Upload to Nutanix Image Service before creating VM

### Step 1.4: Assign IP Addresses

**Power on all VMs, then configure static IPs:**

**On NIDS-Monitor (via console):**
```bash
# Login with credentials you set during Ubuntu install
sudo nano /etc/netplan/00-installer-config.yaml

# Edit to:
network:
  ethernets:
    ens3:  # or eth0, check with 'ip a'
      dhcp4: no
      addresses:
        - 192.168.100.10/24
      gateway4: 192.168.100.1  # Adjust to your gateway
      nameservers:
        addresses:
          - 8.8.8.8
  version: 2

# Save (Ctrl+O, Enter, Ctrl+X)
sudo netplan apply
```

**On Target-Server:**
- Same process, use IP: `192.168.100.20/24`

**On Attacker-Kali:**
- Same process, use IP: `192.168.100.30/24`

**Verify connectivity:**
```bash
# From each VM, ping the others:
ping 192.168.100.10  # NIDS
ping 192.168.100.20  # Target
ping 192.168.100.30  # Attacker
```

---

## 🔧 Phase 2: Software Installation (20 minutes)

### Step 2.1: Setup NIDS Monitor

**On NIDS-Monitor VM:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip git -y

# Create project directory
mkdir ~/nids-project
cd ~/nids-project

# Copy NIDS files (use one of these methods):

# Method A: If you have Git repo
git clone https://github.com/yourusername/NIDS.git
cd NIDS

# Method B: If files are on your laptop
# On your laptop:
scp -r /Users/prethamsai/Future-Ideas/NIDS username@192.168.100.10:~/nids-project/

# Then on NIDS VM:
cd ~/nids-project/NIDS

# Install Python dependencies
pip3 install -r requirements.txt

# Find your network interface
ip a
# Look for interface name (ens3, eth0, etc.)

# Edit config with your interface
nano config/config.yaml
# Change line: interface: "ens3"  # Use YOUR interface name
# Save and exit (Ctrl+O, Enter, Ctrl+X)

# Test NIDS can list interfaces
sudo python3 main.py --list-interfaces
```

### Step 2.2: Setup Target Server

**On Target-Server VM:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install services to attack
sudo apt install openssh-server apache2 vsftpd -y

# Verify services running
sudo systemctl status ssh
sudo systemctl status apache2

# Create a test web page
echo "<h1>Target Server - Test Page</h1>" | sudo tee /var/www/html/index.html

# Test from Target itself
curl http://localhost
```

### Step 2.3: Setup Attacker Machine

**On Attacker-Kali VM:**

```bash
# Kali comes with tools pre-installed, just verify:
nmap --version
hping3 --version

# If missing, install:
sudo apt update
sudo apt install nmap hping3 hydra -y
```

---

## 🧪 Phase 3: Testing the NIDS (30 minutes)

### Step 3.1: Start NIDS and Collect Baseline

**On NIDS-Monitor (open 2 terminals):**

**Terminal 1 - Run NIDS:**
```bash
cd ~/nids-project/NIDS
sudo python3 main.py -i ens3  # Use YOUR interface name
```

**Expected output:**
```
╔═══════════════════════════════════════════════════════════╗
║   Network Intrusion Detection System (NIDS)              ║
╚═══════════════════════════════════════════════════════════╝

[*] Network Interface: ens3
[*] Signature Detection: Enabled
[*] Anomaly Detection: Enabled
[*] Baseline Collection Time: 300 seconds

[*] Loaded 12 attack signatures
[*] Starting packet capture on interface: ens3
[*] Press Ctrl+C to stop
```

**Terminal 2 - Monitor logs:**
```bash
cd ~/nids-project/NIDS
watch -n 1 'ls -lh logs/'
```

### Step 3.2: Generate Normal Traffic (5 minutes)

**During baseline collection, on Target-Server:**
```bash
# Browse some websites
curl http://google.com
curl http://example.com
curl http://ubuntu.com

# SSH to localhost
ssh localhost
# (exit immediately)

# Ping NIDS
ping -c 10 192.168.100.10
```

**On Attacker-Kali (generate normal traffic):**
```bash
# Normal web requests
curl http://192.168.100.20

# Normal ping
ping -c 10 192.168.100.20

# Check if SSH is open
nc -zv 192.168.100.20 22
```

**Wait for baseline to complete (~5 minutes)**

Watch NIDS Terminal 1 for:
```
[*] Establishing baseline from collected data...
[+] Baseline established:
    - Average traffic: 45.23 packets/min
    - Protocol distribution: {'TCP': 0.65, 'UDP': 0.30, 'ICMP': 0.05}
[*] Now monitoring for anomalies...
```

---

### Step 3.3: Run Attack Tests

**Now the fun part! On Attacker-Kali:**

#### 🔴 Test 1: Port Scan (Should trigger alert in ~60 seconds)

```bash
# Basic scan
nmap -p 1-100 192.168.100.20

# Wait and watch NIDS Terminal 1 for alert
```

**Expected alert on NIDS:**
```
================================================================================
ALERT #1 - HIGH SEVERITY
================================================================================
Time: 2024-11-27 14:30:45
Type: port_scan
Description: Port scan detected: 25 unique ports scanned
Source IP: 192.168.100.30
Destination IP: 192.168.100.20

Details:
  port_count: 25
  time_window: 45.2
================================================================================
```

**✅ Success if you see this alert!**

---

#### 🔴 Test 2: SYN Flood (Should trigger alert in ~10 seconds)

```bash
# On Attacker:
sudo hping3 -S --flood -p 80 192.168.100.20 -c 200

# Watch NIDS for CRITICAL alert
```

**Expected alert:**
```
================================================================================
ALERT #2 - CRITICAL SEVERITY
================================================================================
Type: syn_flood
Description: SYN flood detected: 150 SYN packets
Source IP: 192.168.100.30
================================================================================
```

**✅ Success if you see CRITICAL alert!**

---

#### 🔴 Test 3: ICMP Flood (Should trigger alert in ~5 seconds)

```bash
# On Attacker:
sudo hping3 --icmp --flood 192.168.100.20 -c 100

# Or:
sudo ping -f 192.168.100.20
# Press Ctrl+C after 5 seconds
```

**Expected alert:**
```
================================================================================
ALERT #3 - HIGH SEVERITY
================================================================================
Type: icmp_flood
Description: ICMP flood detected: 75 packets
================================================================================
```

**✅ Success if you see HIGH alert!**

---

#### 🔴 Test 4: Web Attack - SQL Injection

```bash
# On Attacker:
curl "http://192.168.100.20/index.php?id=1' OR '1'='1"
curl "http://192.168.100.20/login?user=admin&pass=' OR 1=1--"
```

**Expected alert:**
```
================================================================================
ALERT #4 - HIGH SEVERITY
================================================================================
Type: signature_match
Description: SQL Injection Attempt: Detects common SQL injection patterns
Signature ID: SIG001
================================================================================
```

**✅ Success if you see signature match!**

---

#### 🔴 Test 5: Traffic Volume Anomaly

```bash
# On Attacker, generate high traffic:
for i in {1..50}; do
  curl http://192.168.100.20 &
done

# Wait 60 seconds for window to complete
```

**Expected alert:**
```
================================================================================
ALERT #5 - MEDIUM SEVERITY
================================================================================
Type: traffic_volume_anomaly
Description: Traffic volume anomaly: 250 packets (baseline: 45 ± 10)
================================================================================
```

**✅ Success if you see anomaly alert!**

---

#### 🔴 Test 6: Unusual Port Access

```bash
# On Attacker, access uncommon ports:
nc 192.168.100.20 4444
nc 192.168.100.20 31337
nc 192.168.100.20 6666
```

**Expected alert:**
```
================================================================================
ALERT #6 - LOW SEVERITY
================================================================================
Type: unusual_port_usage
Description: Unusual port usage detected: port 4444
================================================================================
```

**✅ Success if you see low severity alert!**

---

### Step 3.4: Stop NIDS and Review Results

**On NIDS-Monitor Terminal 1:**

Press `Ctrl+C`

**Expected final output:**
```
[*] Shutting down NIDS...
[*] Stopped packet capture. Total packets captured: 5234

============================================================
FINAL STATISTICS
============================================================

Packets Captured: 5234

Signature Detection:
  Loaded Signatures: 12

Anomaly Detection:
  Baseline Established: True
  Anomalies Detected: 8

============================================================
ALERT SUMMARY
============================================================

Total Alerts: 15

By Severity:
  Critical  : 2
  High      : 5
  Medium    : 6
  Low       : 2

By Type:
  port_scan                     : 3
  syn_flood                     : 2
  icmp_flood                    : 1
  signature_match               : 4
  traffic_volume_anomaly        : 3
  unusual_port_usage            : 2

Log File: logs/nids_alerts_20241127_143045.json
============================================================
```

---

## 📊 Phase 4: Verify Results (10 minutes)

### Step 4.1: Check Log Files

**On NIDS-Monitor:**

```bash
# View all alerts
cat logs/nids_alerts_*.json

# Pretty print (if jq installed)
cat logs/nids_alerts_*.json | jq '.'

# Count total alerts
cat logs/nids_alerts_*.json | wc -l

# Search for specific alert types
grep "port_scan" logs/nids_alerts_*.json
grep "syn_flood" logs/nids_alerts_*.json
```

### Step 4.2: Take Screenshots

**Capture these for your project report:**

1. NIDS Monitor showing alerts in real-time
2. Final statistics output
3. Log file contents
4. Attack commands on Attacker VM
5. Network topology (optional - draw diagram)

### Step 4.3: Save Results

```bash
# On NIDS-Monitor, backup everything:
cd ~/nids-project/NIDS

# Create archive
tar -czf nids_test_results_$(date +%Y%m%d).tar.gz logs/

# Copy to your laptop
# On your laptop:
scp username@192.168.100.10:~/nids-project/NIDS/nids_test_results_*.tar.gz ~/Desktop/
```

---

## ✅ Success Checklist

### Setup Phase
- [ ] 3 VMs created in Nutanix
- [ ] Promiscuous mode enabled on NIDS VM
- [ ] All VMs can ping each other
- [ ] NIDS software installed
- [ ] Target server has SSH and HTTP running
- [ ] Attacker has nmap and hping3

### Testing Phase
- [ ] NIDS starts without errors
- [ ] Baseline collected (5 minutes)
- [ ] Port scan detected ✅
- [ ] SYN flood detected ✅
- [ ] ICMP flood detected ✅
- [ ] SQL injection pattern detected ✅
- [ ] Traffic volume anomaly detected ✅
- [ ] Unusual port usage detected ✅

### Results Phase
- [ ] Alert logs created
- [ ] Final statistics displayed
- [ ] Screenshots captured
- [ ] Logs backed up

---

## 🎯 Expected Results Summary

**You should see:**

✅ **Signature-Based Detection:**
- Port scans: 3+ alerts
- SYN floods: 2+ alerts
- ICMP floods: 1+ alert
- SQL injection: 2+ alerts

✅ **Anomaly-Based Detection:**
- Traffic volume anomalies: 3+ alerts
- Unusual port usage: 2+ alerts

✅ **Total Alerts:** 15-20 alerts
✅ **Alert Severities:** Critical, High, Medium, Low
✅ **Log Files:** JSON format with all details

---

## 🐛 Troubleshooting

### No packets captured

```bash
# Check promiscuous mode
sudo ip link set ens3 promisc on
ip link show ens3 | grep PROMISC

# Check interface name
ip a
# Update config/config.yaml with correct interface
```

### No alerts appearing

```bash
# Did baseline complete? (wait 5 full minutes)
# Are attacks aggressive enough?

# Try more aggressive port scan:
nmap -p 1-1000 --min-rate 100 192.168.100.20

# Try longer SYN flood:
sudo hping3 -S --flood -p 80 192.168.100.20 -c 500
```

### Permission errors

```bash
# Always run NIDS with sudo:
sudo python3 main.py -i ens3
```

### Can't ping between VMs

```bash
# Check firewall on each VM:
sudo ufw status

# Disable temporarily for testing:
sudo ufw disable

# Re-enable after testing:
sudo ufw enable
```

---

## 📸 Screenshots to Capture

**For your project documentation:**

1. **Nutanix Prism** - All 3 VMs running
2. **NIDS startup** - Banner and configuration
3. **Baseline collection** - "Baseline established" message
4. **Port scan alert** - High severity
5. **SYN flood alert** - Critical severity
6. **ICMP flood alert** - High severity
7. **SQL injection alert** - Signature match
8. **Traffic anomaly alert** - Medium severity
9. **Final statistics** - Complete summary
10. **Log file** - JSON output showing alerts

---

## 🎓 For Your Project Report

**What you accomplished:**

✅ Built a working Network Intrusion Detection System
✅ Implemented signature-based detection (6 attack types)
✅ Implemented anomaly-based detection (3 techniques)
✅ Tested in realistic network environment (3 VMs)
✅ Successfully detected multiple attack types
✅ Generated comprehensive logs and alerts
✅ Demonstrated real-time monitoring capabilities

**Metrics to include:**
- Total packets analyzed
- Detection accuracy (true positives)
- Alert response time
- Types of attacks detected
- Baseline vs. attack traffic comparison

---

## ⏱️ Time Estimate

```
Phase 1: VM Setup          → 30 minutes
Phase 2: Software Install  → 20 minutes
Phase 3: Testing           → 30 minutes
Phase 4: Results Review    → 10 minutes
──────────────────────────────────────
Total:                       90 minutes
```

**First time**: Plan for 2 hours
**After practice**: Can complete in 60 minutes

---

## 🎉 You're Done!

If you completed all checkboxes, you have:

✅ A fully functional NIDS
✅ Proven detection capabilities
✅ Real attack scenarios tested
✅ Comprehensive logs and results
✅ Screenshots for documentation
✅ Experience with network security testing

**Next steps:**
- Analyze false positive rate
- Tune detection thresholds
- Add more custom signatures
- Write final project report

---

**Questions? Check:**
- `README.md` - Full documentation
- `QUICKSTART.md` - 5-minute overview
- `NUTANIX_TESTING_GUIDE.md` - Detailed testing scenarios
- `PROJECT_OVERVIEW.md` - Technical deep dive

**Good luck with your testing!** 🚀
