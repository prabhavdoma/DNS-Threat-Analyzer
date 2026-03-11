import time
import threading
import os
from datetime import datetime
import analyzer

BLOCKLIST_FILE = "blocklist.txt"

def clean_blocklist():
    """Removes allowlisted domains from the blocklist."""
    if not os.path.exists(BLOCKLIST_FILE):
        return
    
    try:
        valid_lines = []
        with open(BLOCKLIST_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    domain = parts[1]
                    if not analyzer.is_allowlisted(domain):
                        valid_lines.append(line)
                        
        with open(BLOCKLIST_FILE, 'w') as f:
            for line in valid_lines:
                f.write(line)
        print("Blocklist cleaned of any newly allowlisted domains.")
    except Exception as e:
        print(f"Error cleaning blocklist: {e}")

def run_agent():
    """
    AGENTIC LOOP FUNCTION
    
    This function implements a simple autonomous agent loop:
    1. PERCEIVE: It constantly monitors the environment by reading the DNS logs every 30 seconds.
    2. REASON: It analyzes each domain using heuristics to score them. It reasons that any 
       domain with a 'Critical' risk score poses an immediate threat.
    3. ACT: It automatically updates the blocklist file with the new threat without human 
       intervention, effectively "blocking" the domain.
    """
    print("Agent started: Monitoring DNS logs for critical threats...")
    
    # Clean the blocklist on startup
    clean_blocklist()
    
    while True:
        try:
            # Ensure threat feed is loaded
            if not analyzer._threat_domains:
                analyzer.load_threat_feed()
                
            # PERCEIVE: Analyze current log state
            log_path = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')
            if os.path.exists(log_path):
                results = analyzer.analyze_log(log_path)
                
                # REASON: Identify critical threats
                critical_domains = [r['domain'] for r in results if r['risk'] == 'Critical']
                
                # Load existing blocklist to avoid duplicates
                existing_blocks = set()
                if os.path.exists(BLOCKLIST_FILE):
                    with open(BLOCKLIST_FILE, 'r') as f:
                        for line in f:
                            parts = line.strip().split(',')
                            if len(parts) >= 2:
                                existing_blocks.add(parts[1])
                                
                # ACT: Update blocklist with new findings
                new_blocks = 0
                for domain in critical_domains:
                    if domain not in existing_blocks and not analyzer.is_allowlisted(domain):
                        timestamp = datetime.now().isoformat()
                        with open(BLOCKLIST_FILE, 'a') as f:
                            f.write(f"{timestamp},{domain}\n")
                        print(f"[AGENT ALERT] Auto-blocked new critical threat: {domain}")
                        existing_blocks.add(domain)
                        new_blocks += 1
                        
                if new_blocks > 0:
                    print(f"Agent finished cycle: Added {new_blocks} new domains to blocklist.")
                    
        except Exception as e:
            print(f"Agent error in monitoring loop: {e}")
            
        # Wait 30 seconds before next cycle
        time.sleep(30)

def start_agent_thread():
    """Starts the agent monitoring loop in a background daemon thread."""
    agent_thread = threading.Thread(target=run_agent, daemon=True)
    agent_thread.start()
    return agent_thread

if __name__ == "__main__":
    # For testing standalone
    run_agent()
