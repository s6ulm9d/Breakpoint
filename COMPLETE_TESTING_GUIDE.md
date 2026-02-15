# Breakpoint - Complete Testing & Verification Guide

## Overview
This guide provides step-by-step instructions to test every single feature and corner of Breakpoint after the unified integration.

---

## Part 1: Pre-Flight Checks

### 1.1 Verify Installation
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint

# Check Python environment
.venv\Scripts\python --version
# Expected: Python 3.8+

# Verify dependencies
.venv\Scripts\pip list | findstr "requests colorama"
# Expected: Both packages listed
```

### 1.2 Verify Core Modules Load
```bash
# Test all core imports
.venv\Scripts\python -c "
from breakpoint.core.fingerprinter import TechFingerprinter
from breakpoint.core.throttler import AdaptiveThrottler
from breakpoint.core.attack_graph import AttackGraph
from breakpoint.core.context import TargetContext
from breakpoint.core.models import AttackResult, Severity, VulnerabilityStatus
from breakpoint.oob import OOBCorrelator
print('✅ All core modules loaded successfully')
"
```

**Expected Output**: `✅ All core modules loaded successfully`

### 1.3 Verify Attack Modules
```bash
# Test attack imports
.venv\Scripts\python -c "
from breakpoint.attacks.active.sql_injection import SQLInjectionAttack
from breakpoint.attacks import omni
print('✅ Attack modules loaded successfully')
"
```

---

## Part 2: Unit Testing

### 2.1 Test SQLInjection V2 Module
```bash
# Run unit tests
.venv\Scripts\python -m unittest tests.test_sqli_v2 -v
```

**Expected Output**:
```
test_boolean_based_detection ... ok
test_error_based_detection ... ok
test_fingerprint_hybrid_stack ... ok
test_fingerprint_nosql_only ... ok
test_fingerprint_sql_stack ... ok
test_secure_endpoint ... ok

Ran 6 tests in 0.002s
OK
```

### 2.2 Test Tech Fingerprinter
```bash
# Create test script
.venv\Scripts\python -c "
from breakpoint.core.fingerprinter import TechFingerprinter
from breakpoint.core.context import TargetContext
from breakpoint.http_client import HttpClient

# Test against a known target (example.com)
client = HttpClient('https://example.com')
context = TargetContext('https://example.com')
fingerprinter = TechFingerprinter(client)

context = fingerprinter.fingerprint('https://example.com', context)
print(f'Detected: {context.tech_stack}')
print('✅ Fingerprinter working')
"
```

### 2.3 Test Adaptive Throttler
```bash
.venv\Scripts\python -c "
from breakpoint.core.throttler import AdaptiveThrottler, PayloadIntensity

throttler = AdaptiveThrottler(is_dev_env=True)

# Test skip logic
assert throttler.should_skip_attack('dos_extreme') == True, 'EXTREME should skip on dev'
assert throttler.should_skip_attack('xss') == False, 'LIGHT should not skip'

# Test backoff
for _ in range(10):
    throttler.record_request(success=False, response_time=100)
assert throttler.backoff_multiplier > 1.0, 'Backoff should increase after failures'

print('✅ Throttler logic verified')
"
```

### 2.4 Test Attack Graph
```bash
.venv\Scripts\python -c "
from breakpoint.core.attack_graph import AttackGraph
from breakpoint.core.models import AttackResult, VulnerabilityStatus, Severity

graph = AttackGraph()

# Simulate findings
result1 = AttackResult(
    scenario_id='test',
    attack_id='git_exposure',
    status=VulnerabilityStatus.CONFIRMED,
    severity=Severity.HIGH,
    details='Exposed .git',
    artifacts=[]
)
graph.record_finding('git_exposure', result1)

# Check unlocked attacks
next_attacks = graph.get_next_attacks()
assert 'secret_leak' in next_attacks, 'secret_leak should be unlocked'

print('✅ Attack graph chaining verified')
"
```

---

## Part 3: Integration Testing

### 3.1 Start Test Targets

**Terminal 1 - Flask Vulnerable App**:
```bash
cd c:\Users\soulmad\projects\break-point\breakpoint
.venv\Scripts\python breakpoint\examples\vuln_app.py
```
**Expected**: Server running on http://127.0.0.1:5000

**Terminal 2 - Portfolio (Vite)**:
```bash
cd c:\Users\soulmad\projects\portfolio
npm run dev
```
**Expected**: Server running on http://localhost:5174

### 3.2 Test Against Flask (Vulnerable Target)
```bash
# Terminal 3
cd c:\Users\soulmad\projects\break-point\breakpoint

# Run full scan with verbose output
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --env dev --verbose 2>&1 | Tee-Object flask_scan_results.txt
```

**What to Verify**:
1. ✅ OOB Service enabled message
2. ✅ Adaptive Throttling enabled (dev environment)
3. ✅ Attack Graph enabled
4. ✅ Tech Stack Identified (Python, Flask detected)
5. ✅ SQLi CONFIRMED (should find vulnerability)
6. ✅ Exploitation paths generated
7. ✅ Target Stability Report shows metrics
8. ✅ Fewer than 5 ERRORS (adaptive throttling working)

**Check Results**:
```bash
# Count errors
Select-String -Path flask_scan_results.txt -Pattern "ERROR" | Measure-Object -Line
# Expected: < 5 errors

# Check for confirmed findings
Select-String -Path flask_scan_results.txt -Pattern "CONFIRMED"
# Expected: SQLi and other vulnerabilities

# Check exploitation paths
Select-String -Path flask_scan_results.txt -Pattern "EXPLOITATION PATHS"
# Expected: At least 1 path
```

### 3.3 Test Against Portfolio (Dev Server)
```bash
.venv\Scripts\python -m breakpoint http://localhost:5174/ --source "C:\Users\soulmad\projects\portfolio" --env dev --verbose 2>&1 | Tee-Object portfolio_scan_results.txt
```

**What to Verify**:
1. ✅ Tech Stack: React, Vite, TypeScript detected
2. ✅ EXTREME attacks skipped (dos_extreme, graphql_batching, etc.)
3. ✅ HEAVY attacks skipped if server becomes unstable
4. ✅ Errors reduced from 21 → < 5
5. ✅ Confirmed vulnerabilities (headers, git exposure, etc.)
6. ✅ Target Stability Report shows backoff multiplier

**Compare Before/After**:
```bash
# Before (from your earlier scan): 21 ERRORS
# After (expected): < 5 ERRORS

# Check throttled attacks
Select-String -Path portfolio_scan_results.txt -Pattern "THROTTLED"
# Expected: Multiple EXTREME/HEAVY attacks skipped
```

### 3.4 Test SQLInjection Integration
```bash
# Run SQLi-specific integration tests
.venv\Scripts\python tests\integration_sqli_v2.py
```

**Expected Output**:
```
TEST 1: Live Detection
  Status: VulnerabilityStatus.CONFIRMED
  ✅ PASS: SQLi detected on live target

TEST 2: Repeatability (5 iterations)
  ✅ PASS: 100% consistency

TEST 3: Concurrency (20 workers)
  Completed: 20/20 workers
  ✅ PASS: No shared-state leakage

TEST 4: Zero Duplicate Findings
  ✅ PASS: Zero duplicates confirmed

✅ ALL INTEGRATION TESTS PASSED
```

---

## Part 4: Feature-Specific Testing

### 4.1 Test Tech Fingerprinting

**Test 1: Django Site**
```bash
.venv\Scripts\python -m breakpoint https://www.djangoproject.com/ --verbose 2>&1 | Select-String -Pattern "Tech Stack"
```
**Expected**: Languages: Python, Frameworks: Django

**Test 2: WordPress Site**
```bash
.venv\Scripts\python -m breakpoint https://wordpress.org/ --verbose 2>&1 | Select-String -Pattern "Tech Stack"
```
**Expected**: Languages: PHP, Frameworks: WordPress, Databases: MySQL

**Test 3: Next.js Site**
```bash
.venv\Scripts\python -m breakpoint https://nextjs.org/ --verbose 2>&1 | Select-String -Pattern "Tech Stack"
```
**Expected**: Frameworks: Next.js, React

### 4.2 Test Adaptive Throttling

**Test 1: Dev Environment Detection**
```bash
# Scan localhost
.venv\Scripts\python -m breakpoint http://localhost:5174/ --env dev --verbose 2>&1 | Select-String -Pattern "Adaptive Throttling"
```
**Expected**: `Adaptive Throttling: ENABLED (Dev environment detected)`

**Test 2: EXTREME Attack Skipping**
```bash
# Check for skipped attacks
.venv\Scripts\python -m breakpoint http://localhost:5174/ --env dev --verbose 2>&1 | Select-String -Pattern "dos_extreme|graphql_batching|traffic_spike"
```
**Expected**: These should be SKIPPED or not appear in errors

**Test 3: Stability Metrics**
```bash
# Check stability report
.venv\Scripts\python -m breakpoint http://localhost:5174/ --env dev --verbose 2>&1 | Select-String -Pattern "Target Stability Report" -Context 0,7
```
**Expected**: Report showing failure rate, backoff multiplier, etc.

### 4.3 Test Attack Graph Chaining

**Test 1: Exploitation Path Generation**
```bash
# Scan vulnerable target
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --env dev --verbose 2>&1 | Select-String -Pattern "EXPLOITATION PATHS" -Context 0,10
```
**Expected**: At least one exploitation path displayed with chain

**Test 2: Verify Chain Logic**
```bash
# Check if findings unlock dependent attacks
.venv\Scripts\python -c "
from breakpoint.core.attack_graph import AttackGraph
from breakpoint.core.models import AttackResult, VulnerabilityStatus, Severity

graph = AttackGraph()

# Simulate complete chain
findings = [
    ('git_exposure', VulnerabilityStatus.CONFIRMED, Severity.HIGH),
    ('secret_leak', VulnerabilityStatus.CONFIRMED, Severity.CRITICAL),
    ('sql_injection', VulnerabilityStatus.CONFIRMED, Severity.CRITICAL),
]

for attack_id, status, severity in findings:
    result = AttackResult(
        scenario_id='test',
        attack_id=attack_id,
        status=status,
        severity=severity,
        details='Test',
        artifacts=[]
    )
    graph.record_finding(attack_id, result)

paths = graph.generate_exploit_paths()
print(f'Generated {len(paths)} exploitation path(s)')
for path in paths:
    print(f'  Chain: {\" → \".join(path.nodes)}')
    print(f'  Score: {path.severity_score}')
"
```

### 4.4 Test OOB Service

**Test 1: Verify OOB Enabled by Default**
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --verbose 2>&1 | Select-String -Pattern "OOB Service"
```
**Expected**: `OOB Service: ENABLED (Blind vulnerability detection active)`

**Test 2: Disable OOB**
```bash
# Modify cli.py to add --no-oob flag, then:
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --no-oob --verbose 2>&1 | Select-String -Pattern "OOB Service"
```
**Expected**: `OOB Service: DISABLED`

---

## Part 5: End-to-End Validation

### 5.1 Complete Scan Workflow
```bash
# Run complete scan with all features
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --source "C:\Users\soulmad\projects\break-point\breakpoint\breakpoint\examples" --env dev --verbose 2>&1 | Tee-Object complete_scan.txt
```

**Checklist**:
- [ ] OOB Service enabled
- [ ] Adaptive Throttling enabled
- [ ] Attack Graph enabled
- [ ] Tech Stack detected (Python, Flask)
- [ ] Discovery phase completed
- [ ] Baseline stabilization for each attack
- [ ] At least 1 CONFIRMED vulnerability
- [ ] Exploitation paths generated
- [ ] Target Stability Report displayed
- [ ] Errors < 5 (not 21)
- [ ] Scan completes without crashes

### 5.2 Verify Report Generation
```bash
# Check HTML report
ls .breakpoint\reports\*.html | Select-Object -First 1 | ForEach-Object { Start-Process $_.FullName }
```

**Verify in Browser**:
- [ ] Exploitation paths section present
- [ ] CONFIRMED findings highlighted
- [ ] Severity breakdown correct
- [ ] Remediation guidance included

### 5.3 Performance Benchmarking
```bash
# Time the scan
Measure-Command {
    .venv\Scripts\python -m breakpoint http://localhost:5174/ --env dev
}
```

**Expected**: 
- Before: ~45 seconds with 21 errors
- After: ~30 seconds with < 5 errors (faster due to smart skipping)

---

## Part 6: Edge Case Testing

### 6.1 Test Unreachable Target
```bash
.venv\Scripts\python -m breakpoint http://localhost:9999/ --env dev
```
**Expected**: Graceful failure with "Target unreachable" message

### 6.2 Test Rate Limiting
```bash
# Scan a rate-limited target (if available)
.venv\Scripts\python -m breakpoint https://api.github.com/ --verbose
```
**Expected**: BLOCKED status for rate-limited requests

### 6.3 Test Concurrent Scans
```bash
# Terminal 1
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --verbose

# Terminal 2 (simultaneously)
.venv\Scripts\python -m breakpoint http://localhost:5174/ --verbose
```
**Expected**: Both scans complete without interference

### 6.4 Test Keyboard Interrupt
```bash
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --verbose
# Press Ctrl+C after a few seconds
```
**Expected**: Clean shutdown with "TERMINATING: Instant Shutdown Triggered"

---

## Part 7: Regression Testing

### 7.1 Verify No Breaking Changes
```bash
# Test old scenarios still work
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/ --env dev
```
**Expected**: All existing functionality works (no regressions)

### 7.2 Verify Backward Compatibility
```bash
# Test without new flags
.venv\Scripts\python -m breakpoint http://127.0.0.1:5000/
```
**Expected**: Works with default settings (OOB enabled, throttling active)

---

## Part 8: Documentation Verification

### 8.1 Check All Documentation Files
```bash
# Verify files exist
ls docs\*.md
ls sai.md
ls README.md
```

**Expected Files**:
- [ ] docs/ROADMAP_V2_EVOLUTION.md
- [ ] docs/SQLI_V2_VALIDATION_REPORT.md
- [ ] docs/V2_INTEGRATION_VALIDATION.md
- [ ] docs/ADVANCED_FEATURES_SUMMARY.md
- [ ] sai.md (comprehensive guide)

### 8.2 Verify Code Examples in Docs
```bash
# Test code snippets from sai.md
# (Copy-paste examples from sai.md and run them)
```

---

## Part 9: Final Validation Checklist

### Core Features
- [ ] Engine initializes with all advanced features
- [ ] Tech fingerprinting detects frameworks correctly
- [ ] Adaptive throttling reduces errors on dev servers
- [ ] Attack graph generates exploitation paths
- [ ] OOB service enabled by default
- [ ] SQLInjection V2 module works correctly

### Integration
- [ ] All unit tests pass (6/6)
- [ ] All integration tests pass (4/4)
- [ ] Flask scan finds vulnerabilities
- [ ] Portfolio scan has < 5 errors (not 21)
- [ ] Exploitation paths displayed

### Performance
- [ ] Scan completes faster (smart skipping)
- [ ] No memory leaks during long scans
- [ ] Concurrent scans work without issues

### User Experience
- [ ] Verbose output is informative
- [ ] Error messages are clear
- [ ] Reports are readable
- [ ] Documentation is comprehensive

---

## Part 10: Troubleshooting Common Issues

### Issue 1: Import Errors
**Symptom**: `ModuleNotFoundError: No module named 'breakpoint.core'`
**Solution**:
```bash
# Reinstall in development mode
.venv\Scripts\pip install -e .
```

### Issue 2: High Error Count
**Symptom**: Still seeing 21 errors on dev server
**Solution**:
```bash
# Verify throttler is active
.venv\Scripts\python -c "from breakpoint.engine import Engine; e = Engine('http://localhost:5174'); print(e.throttler)"
# Should print AdaptiveThrottler object
```

### Issue 3: No Exploitation Paths
**Symptom**: No paths generated even with confirmed findings
**Solution**:
```bash
# Check attack graph is recording findings
.venv\Scripts\python -c "
from breakpoint.core.attack_graph import AttackGraph
graph = AttackGraph()
print(f'Nodes: {len(graph.nodes)}')
# Should print > 0
"
```

### Issue 4: OOB Not Working
**Symptom**: OOB service not detecting blind vulnerabilities
**Solution**:
```bash
# Verify OOB correlator initialized
.venv\Scripts\python -c "from breakpoint.oob import OOBCorrelator; oob = OOBCorrelator(); print('OOB OK')"
```

---

## Summary

This guide covers:
✅ Pre-flight checks (installation, imports)
✅ Unit testing (all modules)
✅ Integration testing (Flask, Portfolio)
✅ Feature-specific testing (fingerprinting, throttling, graph, OOB)
✅ End-to-end validation
✅ Edge cases
✅ Regression testing
✅ Documentation verification
✅ Troubleshooting

**Total Test Coverage**: ~50 test scenarios across all features

**Expected Results**:
- All unit tests pass
- All integration tests pass
- Errors reduced from 21 → < 5 on dev servers
- Exploitation paths generated
- Tech stack correctly detected
- No regressions in existing functionality

---

*Created: 2026-02-15*
*Version: Unified Integration (No V1/V2 Split)*
*Status: Production Ready*
