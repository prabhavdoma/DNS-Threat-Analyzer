import os
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import tempfile
import analyzer
import agent
import capture
import threading
import datetime
import db

app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# In-memory store for analysis results
_analysis_history = []
_feed_loaded = False

@app.before_request
def initialize_feed():
    """
    Loads the URLhaus threat feed on the first request if it hasn't been loaded yet.
    WHY: Fetching the feed takes a network round-trip. We only want to do this once
    to avoid slowing down every API request.
    """
    global _feed_loaded
    if not _feed_loaded:
        print("Initializing threat feed...")
        analyzer.load_threat_feed()
        db.init_db()
        _feed_loaded = True
        print("Threat feed initialized.")
        print("Starting agent monitoring thread...")
        agent.start_agent_thread(_analysis_history)
        print("Starting DNS capture thread...")
        capture.start_capture()


@app.route('/')
def serve_index():
    """
    Serves the static index.html file.
    WHY: This is the main entry point for the frontend UI to interact with our API.
    """
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/analyze/domain', methods=['POST'])
def analyze_single_domain():
    """
    Accepts JSON {"domain": "example.com"}, analyzes it, and stores the result.
    WHY: Allows the frontend or security analysts to quickly check a single domain
    without needing a full log file.
    """
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' in JSON body"}), 400
        
    domain = data['domain']
    
    # Create an entry similar to a log entry but just for this domain
    entry = {
        "timestamp": "now",
        "client_ip": "manual",
        "domain": domain,
        "query_type": "N/A"
    }
    
    # Score the domain
    analysis = analyzer.score_domain(domain)
    
    # Merge and store
    result = {**entry, **analysis}
    _analysis_history.append(result)
    
    return jsonify(result)

@app.route('/api/analyze/log', methods=['POST'])
def analyze_uploaded_log():
    """
    Accepts a multipart file upload, saves it temporarily, analyzes it, 
    and stores/returns the results.
    WHY: Enables bulk analysis of DNS logs from firewalls or DNS servers,
    providing a centralized way to find threats across many queries at once.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the file
        results = analyzer.analyze_log(filepath)
        
        # Store results in memory
        _analysis_history.extend(results)
        
        # Clean up temp file
        try:
            os.remove(filepath)
        except Exception as e:
            print(f"Error removing temp file {filepath}: {e}")
            
        return jsonify(results)

@app.route('/api/queries', methods=['GET'])
def get_queries():
    """
    Returns the stored query history with an optional risk filter.
    """
    risk_filter = request.args.get('risk', '').lower()
    
    filtered_results = _analysis_history
    if risk_filter:
        filtered_results = [r for r in _analysis_history if r['risk'].lower() == risk_filter]
        
    return jsonify({
        "results": filtered_results
    })

@app.route('/api/summary', methods=['GET'])
def get_summary():
    """
    Returns total captured queries from sample.log, persistent Critical/High
    counts from threats.db, and live feed counts from _analysis_history.
    WHY: Critical/High are persisted in the DB so they reflect all-time detections.
    Medium/Low are transient (only exist in the live feed), so we count them
    from _analysis_history. The donut chart uses the live_* fields to match
    what the user sees in the Live Feed table.
    """
    total_queries = 0
    log_path = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                total_queries = sum(1 for _ in f)
        except Exception as e:
            print(f"Error reading log for summary: {e}")
            
    try:
        db_stats = db.get_stats()
    except Exception as e:
        print(f"Error querying db for summary: {e}")
        db_stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # Count risk levels from the live feed (in-memory analysis of last 50 log entries)
    live_critical = sum(1 for r in _analysis_history if r['risk'] == 'Critical')
    live_high = sum(1 for r in _analysis_history if r['risk'] == 'High')
    live_medium = sum(1 for r in _analysis_history if r['risk'] == 'Medium')
    live_low = sum(1 for r in _analysis_history if r['risk'] == 'Low')
        
    summary = {
        "total": total_queries,
        # Stat cards: Critical/High from DB (persistent), Medium/Low from live feed
        "critical": db_stats.get("Critical", 0),
        "high": db_stats.get("High", 0),
        "medium": live_medium,
        "low": live_low,
        # Donut chart: all counts from live feed so it matches the visible table
        "live_critical": live_critical,
        "live_high": live_high,
        "live_medium": live_medium,
        "live_low": live_low
    }
    
    return jsonify(summary)

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """
    Clears the in-memory analysis history.
    WHY: Allows analysts to reset the tool state before starting a new investigation
    without having to restart the application server.
    """
    global _analysis_history
    _analysis_history = []
    
    return jsonify({"status": "success", "message": "History cleared"})

@app.route('/api/override', methods=['POST'])
def add_override():
    """
    Accepts {"domain": "example.com"} and adds it to the persistent override allowlist.
    """
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' in JSON body"}), 400
        
    domain = data['domain'].lower()
    
    try:
        # Add to override file
        with open(analyzer.OVERRIDE_FILE, 'a') as f:
            f.write(f"{domain}\n")
            
        # Update in-memory history
        for entry in _analysis_history:
            if entry["domain"].lower() == domain or entry["domain"].lower().endswith("." + domain):
                entry["score"] = 0
                entry["risk"] = "Low"
                if "allowlisted" not in entry["flags"]:
                    entry["flags"] = ["allowlisted"]
                
        return jsonify({"status": "success", "message": f"Added {domain} to allowlist"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/allowlist', methods=['GET'])
def get_allowlist_endpoint():
    """
    Returns both hardcoded and override allowlists.
    WHY: Exposing the combined allowlist allows the frontend to show which domains are trusted
    and won't be blocked, differentiating between built-in rules and user overrides.
    """
    hardcoded = list(analyzer.ALLOWLIST)
    overrides = []
    
    if os.path.exists(analyzer.OVERRIDE_FILE):
        try:
            with open(analyzer.OVERRIDE_FILE, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain:
                        overrides.append(domain)
        except Exception:
            pass
            
    return jsonify({
        "hardcoded": hardcoded,
        "overrides": overrides,
        "combined": list(set(hardcoded + overrides))
    })

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """
    Returns all Critical and High detections ever seen from threats.db.
    WHY: Exposes the persistent threat history to the frontend dashboard.
    """
    try:
        threats = db.get_threats()
        return jsonify(threats)
    except Exception as e:
        print(f"Error reading from threats.db: {e}")
        return jsonify([])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Returns query counts bucketed by minute for the last 10 minutes,
    based on the timestamps in sample_logs/sample.log.
    WHY: Feeds data to the frontend line chart, enabling visual tracking of query volume over time.
    """
    stats = {}
    now = datetime.datetime.now()
    
    # Initialize the last 10 minutes with 0
    # We do 0 to 9 to get exactly 10 minutes including current minute
    minute_buckets = []
    for i in range(10):
        dt = now - datetime.timedelta(minutes=i)
        minute_bucket = dt.strftime('%H:%M')
        minute_buckets.append(minute_bucket)
        stats[minute_bucket] = 0

    log_path = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 1:
                        try:
                            ts_str = parts[0]
                            if ts_str.endswith('Z'):
                                ts_str = ts_str.replace('Z', '+00:00')
                                
                            ts = datetime.datetime.fromisoformat(ts_str)
                            
                            # Normalize offset-aware datetimes to naive local to compare with naive now
                            if ts.tzinfo is not None:
                                ts = ts.astimezone().replace(tzinfo=None)
                                
                            # Check if it's within the last 10 minutes (allow slight future differences)
                            delta = now - ts
                            if datetime.timedelta(minutes=-1) <= delta <= datetime.timedelta(minutes=10):
                                minute_bucket = ts.strftime('%H:%M')
                                if minute_bucket in stats:
                                    stats[minute_bucket] += 1
                        except ValueError as ve:
                            pass
        except Exception as e:
            print(f"Error reading log for stats: {e}")
            
    # sort the stats chronologically (oldest to newest)
    sorted_stats = [{"time": bucket, "count": stats[bucket]} for bucket in reversed(minute_buckets)]
    return jsonify(sorted_stats)

if __name__ == '__main__':
    # Ensure static directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
