"""
Vulnerable E-commerce API - Test Target 1
Intentionally vulnerable for security testing

Vulnerabilities:
- SQL Injection (product search)
- JWT Weakness (none algorithm)
- IDOR (view any user's orders)
- XSS (product reviews)
- Missing security headers
"""

from flask import Flask, request, jsonify, make_response
import sqlite3
import jwt
import datetime

app = Flask(__name__)
SECRET_KEY = "super_secret_key_123"  # Weak secret

# Initialize database
def init_db():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products 
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS orders 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, quantity INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reviews 
                 (id INTEGER PRIMARY KEY, product_id INTEGER, user_id INTEGER, comment TEXT)''')
    
    # Insert test data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@shop.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice123', 'alice@shop.com', 'user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'bob', 'bob123', 'bob@shop.com', 'user')")
    
    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'High-performance laptop')")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Mouse', 29.99, 'Wireless mouse')")
    c.execute("INSERT OR IGNORE INTO products VALUES (3, 'Keyboard', 79.99, 'Mechanical keyboard')")
    
    c.execute("INSERT OR IGNORE INTO orders VALUES (1, 2, 1, 1)")
    c.execute("INSERT OR IGNORE INTO orders VALUES (2, 2, 2, 2)")
    c.execute("INSERT OR IGNORE INTO orders VALUES (3, 3, 3, 1)")
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return jsonify({
        "app": "Vulnerable E-commerce API",
        "version": "1.0",
        "endpoints": [
            "/api/login",
            "/api/products/search",
            "/api/orders/<user_id>",
            "/api/products/<product_id>/reviews",
            "/api/admin/users"
        ]
    })

# VULNERABILITY 1: SQL Injection in product search
@app.route('/api/products/search', methods=['GET'])
def search_products():
    query = request.args.get('q', '')
    
    # VULNERABLE: Direct string concatenation
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    
    try:
        c.execute(sql)
        results = c.fetchall()
        conn.close()
        
        products = []
        for row in results:
            products.append({
                "id": row[0],
                "name": row[1],
                "price": row[2],
                "description": row[3]
            })
        
        return jsonify({"products": products})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABILITY 2: JWT with 'none' algorithm accepted
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()
    
    if user:
        # VULNERABLE: Accepts 'none' algorithm
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'role': user[4],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        
        return jsonify({"token": token, "user_id": user[0], "role": user[4]})
    
    return jsonify({"error": "Invalid credentials"}), 401

# VULNERABILITY 3: IDOR - View any user's orders
@app.route('/api/orders/<int:user_id>', methods=['GET'])
def get_orders(user_id):
    # VULNERABLE: No authorization check
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE user_id=?", (user_id,))
    orders = c.fetchall()
    conn.close()
    
    order_list = []
    for order in orders:
        order_list.append({
            "id": order[0],
            "user_id": order[1],
            "product_id": order[2],
            "quantity": order[3]
        })
    
    return jsonify({"orders": order_list})

# VULNERABILITY 4: Stored XSS in product reviews
@app.route('/api/products/<int:product_id>/reviews', methods=['GET', 'POST'])
def product_reviews(product_id):
    if request.method == 'POST':
        data = request.get_json()
        comment = data.get('comment', '')
        user_id = data.get('user_id', 1)
        
        # VULNERABLE: No sanitization
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        c.execute("INSERT INTO reviews (product_id, user_id, comment) VALUES (?, ?, ?)",
                  (product_id, user_id, comment))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Review added"})
    
    else:
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        c.execute("SELECT * FROM reviews WHERE product_id=?", (product_id,))
        reviews = c.fetchall()
        conn.close()
        
        review_list = []
        for review in reviews:
            review_list.append({
                "id": review[0],
                "user_id": review[2],
                "comment": review[3]  # XSS payload returned unsanitized
            })
        
        return jsonify({"reviews": review_list})

# VULNERABILITY 5: Admin endpoint without proper auth
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    # VULNERABLE: Weak JWT verification
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"error": "No token provided"}), 401
    
    try:
        # VULNERABLE: Accepts 'none' algorithm
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256', 'none'])
        
        if payload.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        c.execute("SELECT id, username, email, role FROM users")
        users = c.fetchall()
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[3]
            })
        
        return jsonify({"users": user_list})
    except:
        return jsonify({"error": "Invalid token"}), 401

# VULNERABILITY 6: Missing security headers
@app.after_request
def add_insecure_headers(response):
    # Intentionally missing security headers
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE E-COMMERCE API - TEST TARGET 1")
    print("=" * 60)
    print("Running on: http://127.0.0.1:5001")
    print("\nVulnerabilities:")
    print("  1. SQL Injection: /api/products/search?q=")
    print("  2. JWT Weakness: /api/login (accepts 'none' algorithm)")
    print("  3. IDOR: /api/orders/<user_id>")
    print("  4. XSS: /api/products/<id>/reviews")
    print("  5. Weak Auth: /api/admin/users")
    print("  6. Missing Security Headers")
    print("=" * 60)
    app.run(debug=True, port=5001, host='127.0.0.1')
