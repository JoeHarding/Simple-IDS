# Intrusion Detection System (IDS)

A Python-based Intrusion Detection System that monitors network traffic for suspicious activities and generates alerts.

## Features

- Real-time packet sniffing and analysis
- Port scan detection
- Unusual traffic pattern detection
- Email alerting system
- Real-time monitoring interface
- Comprehensive logging

## Requirements

- Python 3.6 or higher
- scapy
- curses-menu
- python-dotenv

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ids-project
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the system:
   - Edit `config.py` to set your email settings and detection thresholds
   - Update the network interface in `config.py` if needed

## Usage

1. Start the IDS:
```bash
sudo python3 ids.py
```

Note: Root privileges are required for packet sniffing.

2. The system will start monitoring network traffic and display a real-time interface showing:
   - Total packets processed
   - Number of active alerts
   - Recent alerts

3. Press 'q' to quit the monitoring interface

## Configuration

The `config.py` file contains all configurable parameters:

- `ALERT_EMAIL`: Email address for receiving alerts
- `SMTP_SERVER`: SMTP server for sending alerts
- `SUSPICIOUS_PORTS`: List of ports to monitor for suspicious activity
- `PACKET_THRESHOLD`: Number of packets from a single IP to trigger an alert
- `SCAN_THRESHOLD`: Number of port scans to trigger an alert
- `LOG_FILE`: Path to the log file
- `INTERFACE`: Network interface to monitor

## Security Considerations

1. Always run the IDS with appropriate permissions
2. Use environment variables for sensitive information like email credentials
3. Regularly review and update the detection rules
4. Monitor system resources as packet sniffing can be resource-intensive

## Logging

All detected intrusions and system events are logged to the file specified in `config.py`. The log includes:
- Timestamp
- Event type
- Source IP
- Destination IP/Port
- Alert details

## Contributing

Feel free to submit issues and enhancement requests! 