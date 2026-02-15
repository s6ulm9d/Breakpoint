# Comprehensive Breakpoint Testing - 2 Vulnerable Apps

## Test Targets Created

### Target 1: Vulnerable E-commerce API (Port 5001)
**File**: `test_targets/vuln_ecommerce.py`

**Vulnerabilities**:
1. ✅ SQL Injection - `/api/products/search?q=`
2. ✅ JWT Weakness - `/api/login` (accepts 'none' algorithm)
3. ✅ IDOR - `/api/orders/<user_id>` (no authorization)
4. ✅ Stored XSS - `/api/products/<id>/reviews`
5. ✅ Weak Auth - `/api/admin/users`
6. ✅ Missing Security Headers

**Test Data**:
- Users: admin/admin123, alice/alice123, bob/bob123
- Products: Laptop ($999.99), Mouse ($29.99), Keyboard ($79.99)
- Orders: User 2 has orders, User 3 has orders

---

### Target 2: Vulnerable Blog Platform (Port 5002)
**File**: `test_targets/vuln_blog.py`

**Vulnerabilities**:
1. ✅ SSRF - `/api/preview` (fetches any URL)
2. ✅ Arbitrary File Upload - `/api/upload`
3. ✅ Path Traversal (LFI) - `/api/file/<filename>`
4. ✅ Command Injection - `/api/ping`
5. ✅ Open Redirect - `/redirect?url=`
6. ✅ SSTI/RCE - `/render` (template injection)
7. ✅ Debug Exposure - `/api/debug/env`
8. ✅ Git Exposure - `/.git/config`
9. ✅ Missing Security Headers

---

## Test Scenarios

### Scenario 1: E-commerce API - Basic Scan
```bash
# Start app
.venv\Scripts\python test_targets\vuln_ecommerce.py

# Run scan (new terminal)
.venv\Scripts\python -m breakpoint http://127.0.0.1:5001/ --env dev
```

**Expected Results**:
- ✅ OOB Service enabled
- ✅ Adaptive Throttling enabled (dev environment)
- ✅ Attack Graph enabled
- ✅ Tech Stack: Python, Flask detected
- ✅ SQL Injection CONFIRMED
- ✅ JWT Weakness CONFIRMED
- ✅ IDOR CONFIRMED
- ✅ XSS CONFIRMED
- ✅ Missing Headers CONFIRMED
- ✅ Errors < 5 (adaptive throttling working)
- ✅ Exploitation paths generated

### Scenario 2: E-commerce API - Verbose Scan
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5001/ --env dev --verbose
```

**Expected Results**:
- ✅ Detailed fingerprinting output
- ✅ Tech stack breakdown (Languages, Frameworks, Servers)
- ✅ Baseline stabilization messages
- ✅ Attack-by-attack progress
- ✅ Target Stability Report at end
- ✅ Exploitation paths with descriptions

### Scenario 3: E-commerce API - Thorough Scan
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5001/ --env dev --thorough --verbose
```

**Expected Results**:
- ✅ All attacks attempted (no caching)
- ✅ More comprehensive coverage
- ✅ Longer execution time
- ✅ More detailed findings

---

### Scenario 4: Blog Platform - Basic Scan
```bash
# Start app
.venv\Scripts\python test_targets\vuln_blog.py

# Run scan (new terminal)
.venv\Scripts\python -m breakpoint http://127.0.0.1:5002/ --env dev
```

**Expected Results**:
- ✅ SSRF CONFIRMED
- ✅ RCE/SSTI CONFIRMED
- ✅ Open Redirect CONFIRMED
- ✅ LFI CONFIRMED
- ✅ Git Exposure CONFIRMED
- ✅ Debug Exposure CONFIRMED
- ✅ Command Injection CONFIRMED
- ✅ Missing Headers CONFIRMED
- ✅ Exploitation paths (debug → secret leak → RCE)

### Scenario 5: Blog Platform - Verbose Scan
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5002/ --env dev --verbose
```

**Expected Results**:
- ✅ Detailed attack chaining
- ✅ Multiple exploitation paths
- ✅ Stability metrics
- ✅ Comprehensive tech fingerprinting

### Scenario 6: Blog Platform - Thorough Scan
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5002/ --env dev --thorough --verbose
```

**Expected Results**:
- ✅ Maximum coverage
- ✅ All vulnerability types tested
- ✅ Complete exploitation graph

---

## Automated Testing

### Run All Tests Automatically
```bash
.venv\Scripts\python run_comprehensive_tests.py
```

**What It Does**:
1. Starts E-commerce API (port 5001)
2. Runs 3 scans: Basic, Verbose, Thorough
3. Saves results to `test_results_5001_*.txt`
4. Stops E-commerce API
5. Starts Blog Platform (port 5002)
6. Runs 3 scans: Basic, Verbose, Thorough
7. Saves results to `test_results_5002_*.txt`
8. Generates summary report

**Total Tests**: 6 scans (2 apps × 3 modes)

---

## Verification Checklist

### For Each Scan, Verify:
- [ ] OOB Service: ENABLED
- [ ] Adaptive Throttling: ENABLED (Dev environment detected)
- [ ] Attack Graph: ENABLED
- [ ] Tech Stack Identified
- [ ] At least 5 CONFIRMED vulnerabilities
- [ ] Errors < 5 (not 21)
- [ ] EXPLOITATION PATHS section present
- [ ] Target Stability Report (if verbose)
- [ ] Scan completes without crashes

### Advanced Features Working:
- [ ] Tech fingerprinting detects Flask, Python
- [ ] Throttling skips EXTREME attacks on dev
- [ ] Attack graph chains findings
- [ ] Exploitation paths show realistic attack sequences
- [ ] Stability metrics track target health

---

## Expected Exploitation Paths

### E-commerce API
**Path 1**: SQL Injection → Data Exfiltration
**Path 2**: JWT Weakness → IDOR → Data Exfiltration
**Path 3**: XSS → Session Hijacking

### Blog Platform
**Path 1**: Git Exposure → Secret Leak → RCE
**Path 2**: Debug Exposure → Secret Leak → Command Injection
**Path 3**: SSRF → Internal Network Access
**Path 4**: File Upload → RCE

---

## Manual Testing Commands

### Test SQL Injection
```bash
curl "http://127.0.0.1:5001/api/products/search?q=' OR '1'='1"
```

### Test JWT Weakness
```bash
curl -X POST http://127.0.0.1:5001/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
```

### Test IDOR
```bash
curl http://127.0.0.1:5001/api/orders/2
curl http://127.0.0.1:5001/api/orders/3
```

### Test SSRF
```bash
curl -X POST http://127.0.0.1:5002/api/preview -H "Content-Type: application/json" -d "{\"url\":\"http://127.0.0.1:5001/\"}"
```

### Test Open Redirect
```bash
curl "http://127.0.0.1:5002/redirect?url=https://evil.com"
```

### Test Git Exposure
```bash
curl http://127.0.0.1:5002/.git/config
```

---

## Success Criteria

### ✅ All Tests Pass If:
1. Both apps start without errors
2. Breakpoint detects all intentional vulnerabilities
3. Advanced features (OOB, Throttling, Graph) are active
4. Error count < 5 per scan (adaptive throttling working)
5. Exploitation paths generated for both apps
6. No crashes or hangs during scans
7. Reports are generated correctly

### 📊 Expected Findings Summary

**E-commerce API**: 6 vulnerabilities
- SQL Injection (CRITICAL)
- JWT Weakness (HIGH)
- IDOR (HIGH)
- XSS (MEDIUM)
- Weak Auth (HIGH)
- Missing Headers (LOW)

**Blog Platform**: 9 vulnerabilities
- SSRF (HIGH)
- RCE/SSTI (CRITICAL)
- Command Injection (CRITICAL)
- LFI (HIGH)
- Open Redirect (LOW)
- File Upload (CRITICAL)
- Git Exposure (HIGH)
- Debug Exposure (HIGH)
- Missing Headers (LOW)

**Total**: 15 vulnerabilities across 2 apps

---

*Created: 2026-02-15*
*Status: Ready for Testing*
