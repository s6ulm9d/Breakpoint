# Quick Manual Testing Guide - 2 Vulnerable Apps

## ✅ READY TO TEST

I've created 2 vulnerable apps with 15 total vulnerabilities for comprehensive Breakpoint testing.

---

## 🎯 Quick Start (5 Minutes)

### Test 1: E-commerce API

**Terminal 1 - Start App**:
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint
.venv\Scripts\python test_targets\vuln_ecommerce.py
```

**Terminal 2 - Run Breakpoint**:
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint
.venv\Scripts\python -m breakpoint http://127.0.0.1:5001/ --env dev --verbose
```

**Expected Results**:
```
[*] OOB Service: ENABLED
[*] Adaptive Throttling: ENABLED (Dev environment detected)
[*] Attack Graph: ENABLED
[*] PHASE 1: Discovery & Tech Fingerprinting...
    -> Tech Stack Identified:
       • Languages: Python
       • Frameworks: Flask

[... scan runs ...]

CONFIRMED Findings:
  ✅ SQL Injection
  ✅ JWT Weakness
  ✅ IDOR
  ✅ XSS
  ✅ Missing Security Headers

============================================================
EXPLOITATION PATHS DISCOVERED
============================================================
Path 1: SQL Injection → Data Exfiltration
Path 2: JWT Weakness → IDOR → Privilege Escalation

[*] Target Stability Report:
    Errors: < 5 (not 21)
    Status: STABLE
```

---

### Test 2: Blog Platform

**Terminal 1 - Start App**:
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint
.venv\Scripts\python test_targets\vuln_blog.py
```

**Terminal 2 - Run Breakpoint**:
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint
.venv\Scripts\python -m breakpoint http://127.0.0.1:5002/ --env dev --verbose
```

**Expected Results**:
```
CONFIRMED Findings:
  ✅ SSRF
  ✅ RCE/SSTI
  ✅ Command Injection
  ✅ LFI (Path Traversal)
  ✅ Open Redirect
  ✅ Git Exposure
  ✅ Debug Exposure
  ✅ Missing Security Headers

EXPLOITATION PATHS:
Path 1: Git Exposure → Secret Leak → RCE
Path 2: Debug Exposure → Command Injection
Path 3: SSRF → Internal Network Access
```

---

## 📊 What Each App Tests

### E-commerce API (6 Vulnerabilities)
| Vulnerability | Endpoint | Severity |
|--------------|----------|----------|
| SQL Injection | `/api/products/search?q=` | CRITICAL |
| JWT Weakness | `/api/login` | HIGH |
| IDOR | `/api/orders/<user_id>` | HIGH |
| Stored XSS | `/api/products/<id>/reviews` | MEDIUM |
| Weak Auth | `/api/admin/users` | HIGH |
| Missing Headers | All endpoints | LOW |

### Blog Platform (9 Vulnerabilities)
| Vulnerability | Endpoint | Severity |
|--------------|----------|----------|
| SSRF | `/api/preview` | HIGH |
| RCE/SSTI | `/render` | CRITICAL |
| Command Injection | `/api/ping` | CRITICAL |
| LFI | `/api/file/<filename>` | HIGH |
| Open Redirect | `/redirect?url=` | LOW |
| File Upload | `/api/upload` | CRITICAL |
| Git Exposure | `/.git/config` | HIGH |
| Debug Exposure | `/api/debug/env` | HIGH |
| Missing Headers | All endpoints | LOW |

---

## 🔍 Verification Checklist

For each scan, verify:
- [ ] App starts without errors
- [ ] Breakpoint connects successfully
- [ ] OOB Service: ENABLED
- [ ] Adaptive Throttling: ENABLED
- [ ] Attack Graph: ENABLED
- [ ] Tech Stack detected (Python, Flask)
- [ ] At least 5 CONFIRMED vulnerabilities
- [ ] Errors < 5 (adaptive throttling working)
- [ ] EXPLOITATION PATHS section displayed
- [ ] Target Stability Report shown
- [ ] Scan completes without crashes

---

## 🧪 Manual Vulnerability Testing

### Test SQL Injection
```bash
curl "http://127.0.0.1:5001/api/products/search?q=' OR '1'='1"
```
**Expected**: Returns all products (SQL injection successful)

### Test IDOR
```bash
curl http://127.0.0.1:5001/api/orders/2
curl http://127.0.0.1:5001/api/orders/3
```
**Expected**: Can view other users' orders without authentication

### Test SSRF
```bash
curl -X POST http://127.0.0.1:5002/api/preview -H "Content-Type: application/json" -d "{\"url\":\"http://127.0.0.1:5001/\"}"
```
**Expected**: Server fetches internal URL

### Test Git Exposure
```bash
curl http://127.0.0.1:5002/.git/config
```
**Expected**: Returns git configuration

### Test Open Redirect
```bash
curl -I "http://127.0.0.1:5002/redirect?url=https://evil.com"
```
**Expected**: Redirects to external URL

---

## 📈 Success Metrics

### ✅ Tests Pass If:
1. Both apps start successfully
2. Breakpoint detects all vulnerabilities
3. Advanced features active (OOB, Throttling, Graph)
4. Error count < 5 per scan
5. Exploitation paths generated
6. No crashes during scans

### 📊 Expected Totals:
- **Total Vulnerabilities**: 15
- **Critical**: 4 (SQLi, RCE, Command Injection, File Upload)
- **High**: 7 (JWT, IDOR, Weak Auth, SSRF, LFI, Git, Debug)
- **Medium**: 1 (XSS)
- **Low**: 3 (Open Redirect, Missing Headers x2)

---

## 🚀 Next Steps

1. **Start E-commerce App** (Terminal 1)
2. **Run Breakpoint against it** (Terminal 2)
3. **Verify all features working**
4. **Stop E-commerce App**
5. **Start Blog Platform** (Terminal 1)
6. **Run Breakpoint against it** (Terminal 2)
7. **Compare results**

---

*Created: 2026-02-15 18:25*
*Status: Ready for Manual Testing*
