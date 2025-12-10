"""Tiny Flask app to test the 'BREAKPOINT' MVP engine against.

This app is intentionally naive and *not* production ready. It is only for
local experimentation with the engine.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify(status="ok")

@app.route("/echo", methods=["GET"])
def echo():
    return jsonify(message="hello", query=request.args)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Very naive, intentionally simplistic logic for demo purposes.
    # In a real app there would be DB checks, hashing, etc.
    if not username or not password:
        return jsonify(error="missing credentials"), 400

    # Fake "admin" check with intentionally suspicious behavior:
    if "admin" in username.lower():
        # Simulate a clumsy error
        return jsonify(error="internal error for admin-like username"), 500

    return jsonify(message=f"Hello, {username}! (password length={len(password)})")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
