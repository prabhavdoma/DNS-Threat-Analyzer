import os
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import tempfile
import analyzer
import agent
import threading

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
        _feed_loaded = True
        print("Threat feed initialized.")
        print("Starting agent monitoring thread...")
        agent.start_agent_thread()


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

@app.route('/api/load-sample', methods=['POST'])
def load_sample_log():
    """
    Analyzes the built-in sample log, clearing and replacing the history.
    WHY: Provides a quick way to demonstrate the tool's capabilities with
    known good and bad data without needing an external file upload.
    """
    global _analysis_history
    
    sample_path = os.path.join(os.path.dirname(__file__), 'sample_logs', 'sample.log')
    if not os.path.exists(sample_path):
        return jsonify({"error": "Sample log not found"}), 404
        
    # Clear and replace history
    _analysis_history = analyzer.analyze_log(sample_path)
    
    return jsonify(_analysis_history)

@app.route('/api/queries', methods=['GET'])
def get_queries():
    """
    Returns the stored query history with an optional risk filter and a summary.
    WHY: Allows the frontend dashboard to retrieve historical data, filter by 
    severity (e.g., only show Critical), and display aggregate statistics.
    """
    risk_filter = request.args.get('risk', '').lower()
    
    filtered_results = _analysis_history
    if risk_filter:
        filtered_results = [r for r in _analysis_history if r['risk'].lower() == risk_filter]
        
    # Generate summary stats
    summary = {
        "total": len(_analysis_history),
        "critical": sum(1 for r in _analysis_history if r['risk'] == 'Critical'),
        "high": sum(1 for r in _analysis_history if r['risk'] == 'High'),
        "medium": sum(1 for r in _analysis_history if r['risk'] == 'Medium'),
        "low": sum(1 for r in _analysis_history if r['risk'] == 'Low')
    }
    
    return jsonify({
        "summary": summary,
        "results": filtered_results
    })

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

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """
    Reads the blocklist.txt file and returns its contents.
    WHY: Exposes the agent's actions to the frontend dashboard, allowing users
    to see the automated blocklist updates.
    """
    blocklist = []
    if os.path.exists(agent.BLOCKLIST_FILE):
        try:
            with open(agent.BLOCKLIST_FILE, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        blocklist.append({
                            "timestamp": parts[0],
                            "domain": parts[1]
                        })
        except Exception as e:
            print(f"Error reading blocklist: {e}")
            
    return jsonify(blocklist)


if __name__ == '__main__':
    # Ensure static directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
