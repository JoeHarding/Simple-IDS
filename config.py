# IDS Configuration Settings

# Alert Settings
ALERT_EMAIL = "email"
SMTP_SERVER = "smtp dns"
SMTP_PORT = 587

# Detection Rules
SUSPICIOUS_PORTS = [22, 23, 3389]  # SSH, Telnet, RDP
PACKET_THRESHOLD = 100  # Number of packets from a single IP to trigger alert
SCAN_THRESHOLD = 10    # Number of port scans to trigger alert

# Logging Settings
LOG_FILE = "ids_log.txt"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Monitoring Settings
INTERFACE = "eth0"  # Network interface to monitor
FILTER = "ip"      # BPF filter for packet capture 
