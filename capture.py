import threading
import datetime
import os
try:
    from scapy.all import sniff, DNS, DNSQR, IP, IPv6
except ImportError:
    print("Scapy not found. DNS capture will be disabled (expected on Vercel).")
    sniff = None
import analyzer
import db

LOG_FILE = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')
_seen_domains = {}

def _process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            
            # Deduplication Cache (60s TTL)
            # WHY: Modern browsers and OSes often blast 4-5 duplicate DNS queries 
            # (A and AAAA records, retries, etc.) within milliseconds of each other. 
            # We track the last time a domain was seen. If it was seen < 60 seconds ago,
            # we drop it here to prevent flooding the log and skewing our volume statistics.
            now = datetime.datetime.now()
            if domain in _seen_domains:
                if (now - _seen_domains[domain]).total_seconds() < 60:
                    return
            _seen_domains[domain] = now
            
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
            
            # Print for server console debugging
            print(f"Captured DNS query: {domain}")
            
            # Immediately score the domain for high threats
            domain_result = analyzer.score_domain(domain)
            if domain_result['score'] >= 60:
                domain_result['timestamp'] = timestamp
                domain_result['client_ip'] = client_ip
                db.write_threat(domain_result)
            
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
    if sniff is None:
        print("DNS capture disabled: Scapy is missing.")
        return
    t = threading.Thread(target=_run_sniff, daemon=True)
    t.start()
