# DNS Threat Analyzer

A real-time DNS threat detection system that captures live network traffic, scores every query against threat intelligence feeds and heuristic models, and autonomously blocks malicious domains — no human intervention required.

Built as a learning project inspired by Infoblox Threat Defense.

---

## Features

- **Live packet capture** — sniffs real DNS traffic off your network interface using Scapy
- **Dual threat intel feeds** — checks every domain against URLhaus (malware) and OpenPhish (phishing)
- **5 heuristic detectors:**
  - Shannon entropy (catches DGA malware domains)
  - Vowel ratio (secondary DGA signal)
  - Subdomain depth (catches DNS tunneling)
  - Hex pattern detection (catches C2 beaconing)
  - Domain length (catches data exfiltration via DNS)
- **Agentic monitoring loop** — continuously perceives traffic, reasons about threats, and acts by updating a blocklist automatically
- **Persistent threat database** — Critical and High detections stored in SQLite, survive restarts
- **React dashboard** — live feed, flagged detections tab, query volume chart, risk distribution, allowlist management

---

## Setup (Windows)

1. Install [Npcap](https://npcap.com) — required for live packet capture
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run as administrator:
   ```bash
   py app.py
   ```
4. Open `http://localhost:5000`

---

## Architecture

| File | Role |
|---|---|
| `analyzer.py` | Core scoring engine — threat feed lookups + heuristics |
| `capture.py` | Scapy packet sniffer — writes live DNS queries to log |
| `agent.py` | Agentic loop — perceive → reason → act every 20 seconds |
| `app.py` | Flask REST API — serves dashboard and exposes endpoints |
| `db.py` | SQLite persistence — stores all Critical/High detections |

---

## How the Agentic Loop Works

```
capture.py          agent.py              db.py
Live traffic   →   Score domains   →   Persist threats
(perceive)         (reason)             (act)
```

Every 20 seconds the agent reads captured traffic, scores every domain, and writes anything Critical or High to the persistent threat database — without any human input.

---

*Inspired by Infoblox Threat Defense. Built to understand DNS-layer threat detection.*
