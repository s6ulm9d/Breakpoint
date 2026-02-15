"""
Vulnerable Blog Platform - Test Target 2
Intentionally vulnerable for security testing

Vulnerabilities:
- RCE via template injection
- SSRF in URL preview
- Open Redirect
- Arbitrary File Upload
- Path Traversal (LFI)
- Command Injection
"""

from flask import Flask, request, jsonify, redirect, render_template_string
import os
import subprocess
import requests
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return jsonify({
        "app": "Vulnerable Blog Platform",
        "version": "1.0",
        "endpoints": [
            "/api/preview",
            "/api/upload",
            "/api/file/<filename>",
            "/api/ping",
            "/redirect",
            "/render"
        ]
    })

# VULNERABILITY 1: SSRF in URL preview
@app.route('/api/preview', methods=['POST'])
def preview_url():
    data = request.get_json()
    url = data.get('url', '')
    
    # VULNERABLE: No URL validation
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            "status_code": response.status_code,
            "content": response.text[:500],
            "headers": dict(response.headers)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABILITY 2: Arbitrary File Upload
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    
    # VULNERABLE: No file type validation
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return jsonify({
        "message": "File uploaded",
        "filename": filename,
        "path": filepath
    })

# VULNERABILITY 3: Path Traversal (LFI)
@app.route('/api/file/<path:filename>', methods=['GET'])
def get_file(filename):
    # VULNERABLE: No path sanitization
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABILITY 4: Command Injection
@app.route('/api/ping', methods=['POST'])
def ping_host():
    data = request.get_json()
    host = data.get('host', '127.0.0.1')
    
    # VULNERABLE: Direct command execution
    try:
        result = subprocess.check_output(f'ping -n 1 {host}', shell=True, text=True)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABILITY 5: Open Redirect
@app.route('/redirect', methods=['GET'])
def redirect_url():
    target = request.args.get('url', '/')
    
    # VULNERABLE: No URL validation
    return redirect(target)

# VULNERABILITY 6: Server-Side Template Injection (SSTI/RCE)
@app.route('/render', methods=['POST'])
def render_template():
    data = request.get_json()
    template = data.get('template', 'Hello World')
    
    # VULNERABLE: User input in template
    try:
        result = render_template_string(template)
        return jsonify({"rendered": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABILITY 7: Debug endpoint exposing secrets
@app.route('/api/debug/env', methods=['GET'])
def debug_env():
    # VULNERABLE: Exposes environment variables
    return jsonify({
        "environment": dict(os.environ),
        "cwd": os.getcwd(),
        "python_version": os.sys.version
    })

# VULNERABILITY 8: Git exposure
@app.route('/.git/config', methods=['GET'])
def git_config():
    # VULNERABLE: Exposed .git directory
    return """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/vulnerable/blog.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""

# VULNERABILITY 9: Missing security headers
@app.after_request
def add_insecure_headers(response):
    # Intentionally missing security headers
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE BLOG PLATFORM - TEST TARGET 2")
    print("=" * 60)
    print("Running on: http://127.0.0.1:5002")
    print("\nVulnerabilities:")
    print("  1. SSRF: /api/preview")
    print("  2. File Upload: /api/upload")
    print("  3. Path Traversal: /api/file/<filename>")
    print("  4. Command Injection: /api/ping")
    print("  5. Open Redirect: /redirect?url=")
    print("  6. SSTI/RCE: /render")
    print("  7. Debug Exposure: /api/debug/env")
    print("  8. Git Exposure: /.git/config")
    print("  9. Missing Security Headers")
    print("=" * 60)
    app.run(debug=True, port=5002, host='127.0.0.1')
