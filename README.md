# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System that monitors network traffic in real-time, detects potential security threats, and provides comprehensive alerting capabilities.

## Features

### 🔍 Signature-Based Detection
- **Port Scanning Detection**: Identifies horizontal and vertical port scans
- **SYN Flood Detection**: Detects TCP SYN flood attacks
- **ICMP Flood Detection**: Identifies ICMP flooding attempts
- **ARP Spoofing Detection**: Detects ARP poisoning attacks
- **Malicious Payload Detection**: Identifies SQL injection, XSS, and other attack patterns
- **Brute Force Detection**: Monitors failed connection attempts to SSH, RDP, FTP

### 📊 Anomaly-Based Detection
- **Traffic Volume Anomalies**: Statistical analysis to detect unusual traffic patterns
- **Protocol Distribution Anomalies**: Identifies abnormal protocol usage
- **Connection Pattern Analysis**: Detects unusual port usage and connection behavior
- **Baseline Profiling**: Establishes normal traffic patterns for comparison
- **Behavioral Analysis**: Uses statistical methods (standard deviation, Z-scores)

### 📈 Traffic Analysis
- Real-time packet capture and analysis using Scapy
- Protocol distribution statistics
- Top talkers identification
- Port usage analysis
- Connection tracking
- Traffic rate monitoring

### 🚨 Alert Management
- Color-coded severity levels (Critical, High, Medium, Low)
- Real-time console alerts
- JSON/CSV logging
- Detailed threat reports
- Alert statistics and summaries

## Architecture

```
NIDS/
├── src/
│   ├── capture/
│   │   └── packet_sniffer.py          # Packet capture with Scapy
│   ├── detection/
│   │   ├── signature_based.py         # Signature-based detection
│   │   └── anomaly_based.py           # Anomaly-based detection
│   ├── analysis/
│   │   └── traffic_analyzer.py        # Traffic analysis
│   ├── alerts/
│   │   └── alert_manager.py           # Alert handling
│   └── utils/
│       └── helpers.py                 # Utility functions
├── rules/
│   └── signatures.json                # Attack signatures
├── config/
│   └── config.yaml                    # Configuration
├── logs/                              # Alert logs
├── tests/                             # Tests
├── requirements.txt
├── main.py                            # Entry point
└── README.md
```

## Installation

### Prerequisites

- Python 3.7 or higher
- Root/Administrator privileges (required for packet capture)
- macOS, Linux, or Windows

### Step 1: Clone or Download

```bash
cd NIDS
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Configure

Edit `config/config.yaml` to customize:
- Network interface to monitor
- Detection thresholds
- Baseline collection time
- Logging preferences

To find your network interface:
```bash
sudo python3 main.py --list-interfaces
```

## Usage

### Basic Usage

Run with default settings (uses interface from config):
```bash
sudo python3 main.py
```

### Specify Network Interface

```bash
sudo python3 main.py -i eth0
```

### Custom Configuration

```bash
sudo python3 main.py -c custom_config.yaml
```

### List Available Interfaces

```bash
sudo python3 main.py --list-interfaces
```

### Command Line Options

```
usage: main.py [-h] [-i INTERFACE] [-c CONFIG] [--list-interfaces]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to monitor
  -c CONFIG, --config CONFIG
                        Configuration file path
  --list-interfaces     List available network interfaces and exit
```

## Configuration

### Network Settings

```yaml
network:
  interface: "en0"          # Network interface to monitor
  promiscuous_mode: true    # Enable promiscuous mode
  packet_count: 0           # 0 for continuous capture
```

### Signature Detection

```yaml
signature_detection:
  enabled: true

  port_scan:
    enabled: true
    threshold: 20           # Number of unique ports
    time_window: 60         # seconds

  syn_flood:
    enabled: true
    threshold: 100          # SYN packets without ACK
    time_window: 10         # seconds
```

### Anomaly Detection

```yaml
anomaly_detection:
  enabled: true
  baseline_collection_time: 300  # 5 minutes

  traffic_volume:
    enabled: true
    std_deviation_threshold: 3    # Standard deviations

  protocol_distribution:
    enabled: true
    deviation_threshold: 0.3      # 30% deviation
```

## Detection Techniques

### 1. Port Scan Detection

Tracks unique destination ports accessed by each source IP:
- **Threshold**: 20+ ports in 60 seconds
- **Detection Method**: Port counting
- **Severity**: High

### 2. SYN Flood Detection

Monitors SYN packets without corresponding ACK responses:
- **Threshold**: 100+ SYN packets in 10 seconds
- **Detection Method**: SYN/ACK ratio analysis
- **Severity**: Critical

### 3. ICMP Flood Detection

Tracks ICMP packet rates:
- **Threshold**: 50+ ICMP packets in 5 seconds
- **Detection Method**: Packet counting
- **Severity**: High

### 4. ARP Spoofing Detection

Monitors IP-MAC address mappings:
- **Detection Method**: ARP cache inconsistency
- **Severity**: Critical

### 5. Traffic Volume Anomaly

Statistical analysis of packet rates:
- **Detection Method**: Z-score (3+ standard deviations)
- **Severity**: Medium

### 6. Protocol Distribution Anomaly

Compares current protocol usage to baseline:
- **Detection Method**: Frequency deviation (30%+)
- **Severity**: Medium

## Testing the NIDS

### Generate Test Traffic

**Port Scan (using nmap)**:
```bash
nmap -p 1-100 <target_ip>
```

**SYN Flood (using hping3)**:
```bash
sudo hping3 -S --flood -p 80 <target_ip>
```

**ICMP Flood**:
```bash
sudo hping3 --icmp --flood <target_ip>
```

### Verify Detection

Monitor the console output for alerts and check log files in the `logs/` directory.

## Alert Severity Levels

- **🔴 Critical**: SYN floods, ARP spoofing, critical vulnerabilities
- **🟡 High**: Port scans, ICMP floods, brute force attempts
- **🔵 Medium**: Anomalous traffic patterns, unusual protocols
- **🟢 Low**: Informational alerts, minor anomalies

## Log Files

Logs are stored in `logs/` directory with timestamps:
- **JSON format**: `nids_alerts_YYYYMMDD_HHMMSS.json`
- **CSV format**: `nids_alerts_YYYYMMDD_HHMMSS.csv`

Each alert contains:
- Alert ID
- Timestamp
- Type and severity
- Source/destination IPs
- Detailed description
- Additional metadata

## Project Timeline

**Nov. 2024 - May 2025**

- ✅ **Phase 1**: Foundation & packet capture (Weeks 1-2)
- ✅ **Phase 2**: Signature-based detection (Weeks 3-4)
- ✅ **Phase 3**: Anomaly-based detection (Weeks 5-7)
- ⏳ **Phase 4**: Integration & alerting (Weeks 8-9)
- ⏳ **Phase 5**: Testing & documentation (Weeks 10-12)

## Technical Stack

- **Scapy**: Packet manipulation and capture
- **NumPy**: Statistical computations
- **Pandas**: Data analysis
- **PyYAML**: Configuration management
- **Colorama**: Colored terminal output

## Performance Considerations

- **Baseline Collection**: First 5 minutes (configurable)
- **Memory Usage**: Efficient with ring buffers and windowing
- **CPU Usage**: Optimized packet processing
- **Scalability**: Handles moderate traffic loads

## Security Notes

⚠️ **Important Security Considerations**:

1. **Privileges**: NIDS requires root/admin privileges for packet capture
2. **Production Use**: This is an educational/research project
3. **False Positives**: Tune thresholds based on your network
4. **Privacy**: Packet capture may include sensitive data
5. **Legal**: Ensure compliance with network monitoring policies

## Troubleshooting

### Permission Denied

```bash
# Run with sudo
sudo python3 main.py
```

### Interface Not Found

```bash
# List available interfaces
sudo python3 main.py --list-interfaces

# Update config/config.yaml with correct interface
```

### Module Not Found

```bash
# Reinstall dependencies
pip install -r requirements.txt
```

## Future Enhancements

Potential improvements for advanced versions:

- [ ] Machine learning-based anomaly detection
- [ ] Web dashboard for visualization
- [ ] Database integration (PostgreSQL/MongoDB)
- [ ] Email/SMS notifications
- [ ] Distributed NIDS deployment
- [ ] Deep packet inspection (DPI)
- [ ] Integration with SIEM systems
- [ ] Protocol-specific analyzers
- [ ] Geolocation of attackers
- [ ] Automated response mechanisms

## Contributing

This is an educational project developed as part of a Network Security course.

## License

Educational/Research use only.

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [NIST Network Intrusion Detection Guide](https://csrc.nist.gov/)
- Network Security: Private Communication in a Public World

## Author

Developed as part of Network Security Project (Nov. 2024 - May 2025)

---

**Note**: This NIDS is designed for educational purposes and security research. Always ensure proper authorization before monitoring network traffic.
