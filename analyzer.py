import csv
import math
import re
import urllib.request
from urllib.parse import urlparse

# Global set to store known threat domains
_threat_domains = set()
_phishing_domains = set()

# Hardcoded allowlist of trusted domains
ALLOWLIST = {
    "google.com", "github.com", "microsoft.com", 
    "amazon.com", "cloudflare.com", "youtube.com", 
    "stackoverflow.com"
}
OVERRIDE_FILE = "override_allowlist.txt"

def get_allowlist():
    import os
    allowlist = set(ALLOWLIST)
    if os.path.exists(OVERRIDE_FILE):
        try:
            with open(OVERRIDE_FILE, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain:
                        allowlist.add(domain)
        except Exception:
            pass
    return allowlist

def is_allowlisted(domain):
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    base_domain = domain_lower
    if len(parts) >= 2:
        base_domain = f"{parts[-2]}.{parts[-1]}"
    
    current_allowlist = get_allowlist()
    return domain_lower in current_allowlist or base_domain in current_allowlist

def load_threat_feed():
    """
    Downloads the URLhaus malware feed, parses the CSV, extracts domains,
    and stores them in _threat_domains.
    WHY: URLhaus is a reputable source of currently active malware distribution sites.
    Checking against this feed provides high-confidence true positives for malicious activity.
    """
    global _threat_domains
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8').splitlines()
            
            # Skip comments and empty lines
            csv_lines = [line for line in content if line and not line.startswith('#')]
            reader = csv.reader(csv_lines)
            
            for row in reader:
                if len(row) > 2:
                    malware_url = row[2]
                    try:
                        parsed = urlparse(malware_url)
                        if parsed.netloc:
                            # Strip port if present
                            domain = parsed.netloc.split(':')[0]
                            _threat_domains.add(domain.lower())
                    except Exception:
                        continue
    except Exception as e:
        print(f"Error loading URLhaus feed: {e}")
        
    # Load OpenPhish feed
    openphish_url = "https://openphish.com/feed.txt"
    try:
        req = urllib.request.Request(openphish_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8').splitlines()
            for line in content:
                url = line.strip()
                if url:
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0]
                            _phishing_domains.add(domain.lower())
                    except Exception:
                        continue
    except Exception as e:
        print(f"Error loading OpenPhish feed: {e}")

def is_known_malicious(domain):
    """
    Checks if a domain or any of its parent domains exist in _threat_domains.
    WHY: Attackers often use subdomains off a known malicious apex domain.
    If 'bad.com' is listed, 'api.bad.com' should also be flagged.
    """
    domain = domain.lower()
    parts = domain.split('.')
    
    # Check the full domain and all parent domains (at least 2 parts for a valid domain like a.com)
    for i in range(len(parts) - 1):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in _threat_domains:
            return True
            
    return False

def is_known_phishing(domain):
    """
    Checks if a domain or any of its parent domains exist in _phishing_domains.
    """
    domain = domain.lower()
    parts = domain.split('.')
    
    for i in range(len(parts) - 1):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in _phishing_domains:
            return True
            
    return False

def shannon_entropy(s):
    """
    Computes Shannon entropy of a string.
    WHY: Normal domains consist of somewhat predictable language components,
    resulting in lower entropy. Domain Generation Algorithms (DGAs) usually
    produce random-looking strings with an even distribution of characters,
    resulting in high entropy.
    """
    if not s:
        return 0
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def subdomain_depth(domain):
    """
    Counts how many subdomain levels a domain has beyond the base domain + TLD.
    WHY: Attackers often use long, deeply nested subdomains for data exfiltration
    via DNS tunnels (e.g., secret-data.b64.evil.com) or to evade simple domain blocks.
    Normal domains typically have 0-2 subdomains (e.g., www.example.com or app.dev.example.com).
    """
    parts = domain.split('.')
    # Assume the last two parts are the base domain + TLD (e.g., 'example.com')
    # This is a simplification; a full solution would use the Public Suffix List.
    if len(parts) <= 2:
        return 0
    return len(parts) - 2

def has_hex_pattern(domain):
    """
    Returns True if the domain contains a hex string 16+ characters long.
    WHY: Malware and botnets frequently use hardcoded hex strings, UUIDs, or 
    hashes as subdomains for command-and-control (C2) infrastructure or DGA seeds
    (e.g., 5f4dcc3b5aa765d61d8327deb882cf99.com).
    """
    # Regex matches 16 or more consecutive hex characters (0-9, a-f)
    return bool(re.search(r'[0-9a-f]{16,}', domain.lower()))

def is_dga_likely(label):
    """
    Returns True if a domain label has less than 20% vowels and is longer than 8 characters.
    WHY: Randomly generated strings (DGAs) usually lack the consonant/vowel structure 
    inherent in human languages, leading to statistically fewer vowels. Length is 
    checked to avoid flagging short, valid acronyms (e.g., 'crvt').
    """
    if len(label) <= 8:
        return False
        
    vowels = set('aeiou')
    vowel_count = sum(1 for char in label.lower() if char in vowels)
    
    # Calculate vowel ratio
    ratio = vowel_count / len(label)
    return ratio < 0.20

def score_domain(domain):
    """
    Runs heuristics and assigns a risk score and severity based on triggered signals.
    WHY: Combining multiple weak signals (like depth or entropy) or a single strong 
    signal (like a known threat match) gives a more robust indication of malicious intent
    than relying on any single metric.
    Than relying on any single metric.
    """
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    
    # 0. Check Allowlist first
    if is_allowlisted(domain):
        return {
            "domain": domain,
            "score": 0,
            "risk": "Low",
            "flags": ["allowlisted"],
            "entropy": round(shannon_entropy(domain), 3),
            "subdomain_depth": subdomain_depth(domain)
        }

    score = 0
    flags = []
    
    # 1. Check known malicious feed (Strong signal)
    if is_known_malicious(domain):
        score += 100
        flags.append("Threat Feed Match")
        
    # 2. Check Entropy (Medium signal)
    ent = shannon_entropy(domain)
    if ent > 4.5:
        # High entropy likely indicates DGA or encoding
        score += 40
        flags.append(f"High Entropy ({ent:.2f})")
    elif ent > 4.0:
        score += 20
        flags.append(f"Elevated Entropy ({ent:.2f})")
        
    # 3. Check Subdomain Depth (Medium/Weak signal)
    depth = subdomain_depth(domain)
    if depth >= 5:
        score += 50
        flags.append(f"Excessive Subdomains ({depth})")
    elif depth >= 3:
        score += 20
        flags.append(f"High Subdomains ({depth})")
        
    # 4. Check Hex Pattern (Strong signal)
    if has_hex_pattern(domain):
        score += 60
        flags.append("Hex String Pattern detected")
        
    # 5. Check DGA likelihood on the base domain label
    parts = domain.split('.')
    if len(parts) >= 2:
        base_label = parts[-2]
        if is_dga_likely(base_label):
            score += 45
            flags.append("DGA Likely (Low Vowel Ratio)")
            
    # 6. Check OpenPhish Feed (Strong signal)
    if is_known_phishing(domain):
        score += 70
        flags.append("known_phishing_feed")
            
    # Cap score at 100
    score = min(score, 100)
    
    # Determine risk level
    if score >= 80:
        risk = "Critical"
    elif score >= 50:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"
        
    return {
        "domain": domain,
        "score": score,
        "risk": risk,
        "flags": flags,
        "entropy": round(ent, 3),
        "subdomain_depth": depth
    }

def parse_dns_log(filepath):
    """
    Reads the sample log file and returns a list of dictionaries representing each entry.
    WHY: We need to normalize raw log formats into structured data before analysis.
    """
    entries = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    entries.append({
                        "timestamp": parts[0],
                        "client_ip": parts[1],
                        "domain": parts[2],
                        "query_type": parts[3]
                    })
    except Exception as e:
        print(f"Error reading log file {filepath}: {e}")
        
    return entries

def analyze_log(filepath):
    """
    Calls parse_dns_log and score_domain on each entry, merges the results, 
    and returns them sorted by score descending.
    WHY: This ties together the parsing and analysis phases into a single executable flow,
    sorting by risk so analysts can prioritize the most critical alerts first.
    """
    # Load threat feed before starting analysis
    if not _threat_domains:
        load_threat_feed()
        
    entries = parse_dns_log(filepath)
    results = []
    
    for entry in entries:
        analysis = score_domain(entry["domain"])
        # Merge dictionary
        merged = {**entry, **analysis}
        results.append(merged)
        
    # Sort descending by score
    results.sort(key=lambda x: x["score"], reverse=True)
    return results

if __name__ == "__main__":
    # Test execution
    logs = analyze_log("sample_logs/sample.log")
    for log in logs:
        print(f"[{log['risk'].upper()}] {log['domain']} (Score: {log['score']}) - Flags: {', '.join(log['flags'])}")
