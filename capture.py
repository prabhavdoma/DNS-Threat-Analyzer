import threading
import datetime
import os
from scapy.all import sniff, DNS, DNSQR, IP, IPv6

LOG_FILE = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')

def _process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            qtype = packet[DNSQR].qtype
            
            # Map common qtypes to strings, fallback to integer
            qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
            qtype_name = qtype_map.get(qtype, str(qtype))
            
            client_ip = "Unknown"
            if packet.haslayer(IP):
                client_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                client_ip = packet[IPv6].src
                
            timestamp = datetime.datetime.now().isoformat()
            
            print(f"Captured DNS query: {domain}")
            
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, 'a') as f:
                f.write(f"{timestamp} {client_ip} {domain} {qtype_name}\n")
        except Exception as e:
            print(f"Error processing packet: {e}")

def _run_sniff():
    print("Starting DNS sniffer on port 53...")
    # sniff blocks and captures packets match filter
    sniff(filter="port 53", prn=_process_packet, store=0)

def start_capture():
    t = threading.Thread(target=_run_sniff, daemon=True)
    t.start()
