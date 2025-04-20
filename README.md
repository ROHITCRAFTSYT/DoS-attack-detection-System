# Advanced DoS Attack Detection System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-brightgreen)
![Status](https://img.shields.io/badge/status-active-success.svg)

A robust, comprehensive system for real-time detection and analysis of Denial-of-Service (DoS) attacks on network infrastructure.

## 🚀 Features

- **Multi-Vector Detection**: Identifies various DoS attack types:
  - SYN Floods
  - UDP Floods
  - ICMP Floods
  - HTTP/Application Layer Floods
  - Volumetric Attacks
  - Distributed DoS (DDoS)
  - Targeted Attacks
  - Port Scanning

- **Advanced Analytics**:
  - Traffic rate analysis with adaptive thresholds
  - Protocol distribution monitoring
  - TCP flag pattern recognition
  - Shannon entropy calculation for source/destination IPs
  - Half-open connection tracking
  - Dynamic baseline comparison

- **Visualization & Reporting**:
  - Real-time traffic statistics
  - JSON-formatted alerts
  - Attack pattern summarization
  - Baseline deviation metrics

- **Flexible Deployment**:
  - Live network interface monitoring
  - PCAP file analysis for forensics
  - Adjustable detection parameters

## 📋 Requirements

- Python 3.6+
- Dependencies:
  - scapy
  - numpy
  - pandas

## 🔧 Installation

1. Clone this repository:
```bash
git clone https://github.com/ROHITCRAFTSYT/dos-detection-system.git
cd dos-detection-system
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Basic Usage

Monitor a network interface:
```bash
python dos_detection.py -i eth0
```

Analyze a PCAP file:
```bash
python dos_detection.py -p capture.pcap
```

### Advanced Options

```bash
python dos_detection.py -i eth0 -o results.json -w 120 -t 0.8 -m
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-i, --interface` | Network interface to monitor | None |
| `-p, --pcap` | PCAP file to analyze | None |
| `-o, --output` | Output file for detection results | dos_detection_results.json |
| `-b, --baseline` | Baseline file for normal traffic patterns | baseline.pkl |
| `-w, --window` | Time window size in seconds for traffic analysis | 60 |
| `-t, --threshold` | Alert threshold (0.0-1.0) | 0.7 |
| `-m, --mitigate` | Enable automatic mitigation responses | False |

## 📊 How It Works

### Detection Methodology

1. **Traffic Capture**: Intercepts network packets using Scapy
2. **Statistical Analysis**: Calculates key metrics:
   - Packets/bytes per second
   - Protocol distribution percentages
   - Flag patterns in TCP traffic
   - Connection establishment rates
3. **Pattern Recognition**: Identifies anomalies:
   - Sudden traffic spikes
   - Abnormal protocol ratios
   - Suspicious flag combinations
   - Unusual source/destination entropy
4. **Baseline Comparison**: Compares current patterns against normal traffic baseline
5. **Alert Generation**: Raises detailed alerts when attack patterns are detected

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  Packet Capture │───>│Statistical Engine│───>│ Pattern Analysis │
└─────────────────┘    └─────────────────┘    └──────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  Alert Logging  │<───│ Decision Engine │<───│Baseline Comparison│
└─────────────────┘    └─────────────────┘    └──────────────────┘
        │                      │
        ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│ JSON Output File│    │Mitigation Module│
└─────────────────┘    └─────────────────┘
```

## 🛡️ Attack Types & Detection Methods

### SYN Flood Detection
Monitors the ratio of SYN flags and tracks half-open connections to identify TCP SYN floods.

### UDP Flood Detection
Analyzes UDP packet rates and their proportion relative to other protocols.

### HTTP Flood Detection
Examines connection patterns to common HTTP ports (80, 443, 8080, 8443).

### Volumetric Attack Detection
Monitors overall traffic volume and compares against baseline thresholds.

### Distributed Attack Detection
Uses Shannon entropy analysis of source IP addresses to detect distributed attacks.

### Targeted Attack Detection
Analyzes destination IP entropy to identify attacks focused on specific targets.

## 📈 Sample Output

```json
{
  "status": "ALERT",
  "traffic": {
    "packets_per_sec": 2547.82,
    "bytes_per_sec": 1546238.45,
    "total_packets": 82731,
    "unique_src_ips": 347,
    "unique_dst_ips": 3,
    "protocol_distribution": {
      "tcp": 98.73,
      "udp": 0.89,
      "icmp": 0.11,
      "other": 0.27
    }
  },
  "alerts": [
    {
      "type": "SYN FLOOD",
      "message": "Detected 3241 half-open connections with SYN ratio: 0.92"
    },
    {
      "type": "TARGETED ATTACK",
      "message": "Low destination IP entropy: 0.37, unique dest IPs: 3"
    }
  ],
  "timestamp": "2025-04-20T15:23:47.123456"
}
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Acknowledgements

- [Scapy](https://scapy.net/) for packet manipulation
- [NumPy](https://numpy.org/) for mathematical operations
- [Pandas](https://pandas.pydata.org/) for data analysis
