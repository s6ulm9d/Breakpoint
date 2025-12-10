from flask import Flask, request, jsonify

# ⚠️  EDUCATIONAL VULNERABLE APP
# DO NOT RUN ON PUBLIC NETWORKS
# Intentionally naive to demonstrate BREAKPOINT engine.

app = Flask(__name__)

@app.route('/')
def home():
    # Vulnerability: Missing security headers
    return "<h1>Vulnerable App Home</h1><p>Welcome to the lab.</p>"

@app.route('/login', methods=['POST'])
def login():
    # Vulnerability: No rate limiting, always returns 401 for wrong credentials
    # Does not simulate 429 ever.
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/search')
def search():
    # Vulnerability: Reflected XSS (Naive reflection of 'q')
    q = request.args.get('q', '')
    return f"<h1>Search Results for: {q}</h1>"

@app.route('/api/tracker', methods=['POST'])
def tracker():
    # Vulnerability: Simulates unsafe deserialization RCE (React2Shell pattern)
    # If the payload contains the special BP probe, we 'execute' it.
    data = request.get_json(force=True, silent=True) or {}
    val = data.get('tracker', '')
    
    if "_$$ND_FUNC$$_" in val and "BP_SAFE_PROBE" in val:
        # Simulate execution
        return jsonify({"status": "processed", "result": "BP_SAFE_PROBE"}), 200
        
    return jsonify({"status": "ok"}), 200

@app.route('/api/products')
def products():
    # Vulnerability: Blind SQL Injection (Simulated)
    # If the user passes a specific payload, we simulate a DB error or bypass behavior.
    cat = request.args.get('category', '')
    
    # 1. Error Based simulation
    if "'" in cat and not "1=1" in cat:
        return "ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", 500
        
    # 2. Logic Bypass simulation
    if "OR '1'='1" in cat or "OR 1=1" in cat:
        return "id:1, name:Admin Product\nid:2, name:User Product\nid:3, name:Hidden Item", 200
        
    return "id:2, name:User Product", 200

@app.route('/api/fetch_url', methods=['POST'])
def fetch_url():
    # Vulnerability: SSRF
    # Allows fetching arbitrary URLs including local files
    data = request.get_json(force=True, silent=True) or {}
    url = data.get('url', '')
    
    if url.startswith("file:///etc/passwd"):
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", 200
        
    if "127.0.0.1" in url or "localhost" in url:
        return "INTERNAL DASHBOARD ACCESSED", 200
        
    return f"Fetched content from {url}", 200
    
if __name__ == '__main__':
    print("🔒 Starting Vulnerable Lab App on 127.0.0.1:5000...")
    app.run(host='127.0.0.1', port=5000)
