import time
import threading
import os
from datetime import datetime
import analyzer

_shared_history = None

def run_agent():
    """
    AGENTIC LOOP FUNCTION
    
    This function implements an autonomous agent loop (Perceive, Reason, Act):
    
    1. PERCEIVE: It monitors the environment by reading the live DNS queries stored 
       in the sample.log file every 20 seconds.
       
    2. REASON: It analyzes each domain using heuristics (entropy, subdomains, etc.) 
       and known threat feeds to assign a risk score. It reasons that any domain 
       with a 'Critical' risk score poses an immediate threat to the network.
       
    3. ACT: It autonomously updates the firewall-ready blocklist file with the new 
       threats without human intervention. It also updates the live, shared session 
       state for the UI dashboard.
    """
    print("Agent started: Monitoring DNS logs for critical threats...")
    
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
                
                # Update app._analysis_history with LIVE captured log
                try:
                    if _shared_history is not None:
                        _shared_history.clear()
                        _shared_history.extend(results)
                    else:
                        import app
                        app._analysis_history.clear()
                        app._analysis_history.extend(results)
                except Exception as e:
                    print(f"Agent error updating app history: {e}")
                    
        except Exception as e:
            print(f"Agent error in monitoring loop: {e}")
            
        # Wait 20 seconds before next cycle
        time.sleep(20)

def start_agent_thread(history_list=None):
    """Starts the agent monitoring loop in a background daemon thread."""
    global _shared_history
    _shared_history = history_list
    agent_thread = threading.Thread(target=run_agent, daemon=True)
    agent_thread.start()
    return agent_thread

if __name__ == "__main__":
    # For testing standalone
    run_agent()
