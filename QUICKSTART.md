# NIDS Quick Start Guide

## Installation & Setup (5 minutes)

### 1. Install Dependencies

```bash
cd /Users/prethamsai/Future-Ideas/NIDS
pip install -r requirements.txt
```

### 2. Find Your Network Interface

```bash
sudo python3 main.py --list-interfaces
```

Example output:
```
Available network interfaces:
  1. en0
  2. en1
  3. lo0
```

### 3. Update Configuration

Edit `config/config.yaml` and set your interface:

```yaml
network:
  interface: "en0"  # Change this to your interface
```

### 4. Run NIDS

```bash
sudo python3 main.py
```

## What to Expect

### Phase 1: Baseline Collection (First 5 minutes)

The system will collect baseline traffic data:
```
[*] Collecting baseline traffic patterns...
[*] Baseline collection: 150/300 seconds
```

### Phase 2: Active Monitoring

After baseline is established, you'll see:
```
[+] Baseline established:
    - Average traffic: 45.23 packets/min
    - Protocol distribution: {'TCP': 0.65, 'UDP': 0.30, 'ICMP': 0.05}
[*] Now monitoring for anomalies...
```

### Alert Examples

**Port Scan Detected:**
```
================================================================================
ALERT #1 - HIGH SEVERITY
================================================================================
Time: 2024-11-15 14:30:45
Type: port_scan
Description: Port scan detected: 25 unique ports scanned
Source IP: 192.168.1.100
Destination IP: 192.168.1.1

Details:
  port_count: 25
  time_window: 45.2
================================================================================
```

**Traffic Volume Anomaly:**
```
================================================================================
ALERT #2 - MEDIUM SEVERITY
================================================================================
Time: 2024-11-15 14:35:10
Type: traffic_volume_anomaly
Description: Traffic volume anomaly: 150 packets (baseline: 45 ± 10)

Details:
  current_volume: 150
  baseline_mean: 45.0
  baseline_std: 10.0
  deviation: 10.5
================================================================================
```

## Testing Your NIDS

### Test 1: Generate Normal Traffic

Open a browser and visit a few websites. You should see:
- Traffic statistics updating every minute
- No alerts (traffic is normal)

### Test 2: Simulate Port Scan

```bash
# From another machine or terminal
nmap -p 1-50 <your_machine_ip>
```

Expected: Port scan alert

### Test 3: Generate High Traffic

```bash
# Download a large file or run multiple downloads simultaneously
```

Expected: Traffic volume anomaly alert

## Common Commands

### Run with specific interface
```bash
sudo python3 main.py -i eth0
```

### Use custom config
```bash
sudo python3 main.py -c my_config.yaml
```

### View logs
```bash
cat logs/nids_alerts_*.json | jq '.'  # If you have jq installed
# or
cat logs/nids_alerts_*.json
```

### Stop NIDS
Press `Ctrl+C`

## Troubleshooting

### "Permission denied"
→ Run with `sudo`

### "No module named 'scapy'"
→ Run `pip install -r requirements.txt`

### "Interface not found"
→ Run `sudo python3 main.py --list-interfaces` and update config

### Too many false positives
→ Increase thresholds in `config/config.yaml`

### No alerts appearing
→ Wait for baseline collection to complete (5 minutes)
→ Check if detection is enabled in config

## Understanding Output

### Statistics Display (Every 60 seconds)

```
============================================================
TRAFFIC STATISTICS
============================================================

Total Packets Captured: 1234
Elapsed Time: 120.50 seconds
Traffic Rate: 10.24 packets/sec
Average Packet Size: 512.00 bytes

Protocol Distribution:
  TCP       :    800 packets (64.83%)
  UDP       :    350 packets (28.36%)
  ICMP      :     84 packets (6.81%)

Top Source IPs (Top Talkers):
  192.168.1.100        :    456 packets (36.98%)
  192.168.1.101        :    234 packets (18.96%)
```

### Alert Summary (On Exit)

```
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
  traffic_volume_anomaly        : 4
  unusual_port_usage            : 8

Log File: logs/nids_alerts_20241115_143045.json
============================================================
```

## Next Steps

1. **Tune Configuration**: Adjust thresholds based on your network
2. **Add Custom Signatures**: Edit `rules/signatures.json`
3. **Analyze Logs**: Review alert logs for patterns
4. **Test Attacks**: Safely simulate various attacks in a test environment
5. **Extend Features**: Add new detection rules or analysis capabilities

## Tips

- **Let it run for at least 10 minutes** to get meaningful baseline data
- **Normal traffic varies** - adjust thresholds for your environment
- **Check logs regularly** - `logs/` directory contains all alerts
- **Monitor resource usage** - Use `top` or Activity Monitor
- **Test safely** - Only test on networks you own or have permission to test

## Resources

- Full documentation: `README.md`
- Configuration reference: `config/config.yaml`
- Signature database: `rules/signatures.json`

---

**Ready to start?** Run: `sudo python3 main.py`
