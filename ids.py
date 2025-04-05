#!/usr/bin/env python3

import logging
import smtplib
import curses
import time
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from config import *

# Initialize logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format=LOG_FORMAT
)

class IntrusionDetectionSystem:
    def __init__(self):
        self.packet_count = defaultdict(int)
        self.port_scan_count = defaultdict(int)
        self.alerts = []

    def send_alert(self, subject, body):
        """Send email alert for detected intrusions"""
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = ALERT_EMAIL
        msg['To'] = ALERT_EMAIL

        try:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.login(ALERT_EMAIL, 'your_password')  # Use environment variables in production
                server.send_message(msg)
            logging.info(f"Alert sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send alert: {str(e)}")

    def detect_port_scan(self, packet):
        """Detect potential port scanning activity"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            if dst_port in SUSPICIOUS_PORTS:
                self.port_scan_count[src_ip] += 1
                
                if self.port_scan_count[src_ip] >= SCAN_THRESHOLD:
                    alert_msg = f"Port scan detected from {src_ip} to port {dst_port}"
                    logging.warning(alert_msg)
                    self.send_alert("Port Scan Detected", alert_msg)
                    self.alerts.append(alert_msg)

    def detect_unusual_traffic(self, packet):
        """Detect unusual traffic patterns"""
        if IP in packet:
            src_ip = packet[IP].src
            self.packet_count[src_ip] += 1
            
            if self.packet_count[src_ip] >= PACKET_THRESHOLD:
                alert_msg = f"Unusual traffic pattern detected from {src_ip}"
                logging.warning(alert_msg)
                self.send_alert("Unusual Traffic Detected", alert_msg)
                self.alerts.append(alert_msg)

    def packet_callback(self, packet):
        """Main packet processing callback"""
        self.detect_port_scan(packet)
        self.detect_unusual_traffic(packet)

    def start_monitoring(self):
        """Start the IDS monitoring"""
        logging.info("Starting IDS monitoring...")
        try:
            sniff(iface=INTERFACE, filter=FILTER, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            logging.info("IDS monitoring stopped by user")
        except Exception as e:
            logging.error(f"Error in monitoring: {str(e)}")

def real_time_monitoring(stdscr, ids):
    """Display real-time monitoring interface"""
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(100)

    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break

        stdscr.clear()
        stdscr.addstr(0, 0, "Real-Time Network Monitoring")
        stdscr.addstr(1, 0, f"Total Packets Processed: {sum(ids.packet_count.values())}")
        stdscr.addstr(2, 0, f"Active Alerts: {len(ids.alerts)}")
        
        # Display recent alerts
        stdscr.addstr(4, 0, "Recent Alerts:")
        for i, alert in enumerate(ids.alerts[-5:], 1):
            stdscr.addstr(4 + i, 0, f"{i}. {alert}")
        
        stdscr.addstr(10, 0, "Press 'q' to quit")
        stdscr.refresh()

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    
    # Start monitoring in a separate thread
    import threading
    monitor_thread = threading.Thread(target=ids.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Start the monitoring interface
    curses.wrapper(real_time_monitoring, ids) 