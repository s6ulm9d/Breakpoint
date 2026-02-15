# Integration Validation Framework for V2 Engine

## Status: APPROVED FOR STAGED INTEGRATION
**NOT YET**: APPROVED FOR ENGINE INTEGRATION

---

## Validation Checklist

### ✅ Phase 1: Unit Validation (COMPLETE)
- [x] Contract integrity
- [x] Deterministic behavior
- [x] Architecture compliance

### 🔄 Phase 2: Integration Validation (IN PROGRESS)

#### 1️⃣ Live Target Testing
- [ ] Flask vuln_app.py validation
- [ ] DVWA validation
- [ ] Consistent detection across targets
- [ ] Zero duplicate findings

#### 2️⃣ Repeatability Testing
- [ ] Execute 5 identical scans
- [ ] Verify identical AttackResult output
- [ ] Confirm timing logic stability (no oscillation)

#### 3️⃣ Concurrency Testing
- [ ] Run with 20+ workers
- [ ] Verify no shared-state leakage
- [ ] Confirm context isolation per thread

#### 4️⃣ Baseline + Stabilizer Interaction
- [ ] Enable ResponseStabilizer
- [ ] Confirm SQL errors not masked
- [ ] Verify delta logic integrity

#### 5️⃣ Engine Compatibility (V1 vs V2)
- [ ] Side-by-side execution
- [ ] Detection coverage comparison
- [ ] False positive rate comparison
- [ ] Execution time comparison
- [ ] Evidence artifact comparison

#### 6️⃣ Resource Profiling
- [ ] Memory usage snapshot
- [ ] CPU usage snapshot
- [ ] Payload explosion check

---

## Shadow Mode Implementation

### Architecture
```
┌─────────────┐
│   Engine    │
├─────────────┤
│ V1 (Primary)│ ──► Report
│ V2 (Shadow) │ ──► Comparison Log (Silent)
└─────────────┘
```

### CLI Flag
```bash
breakpoint scan --engine v2 --shadow-mode
```

### Behavior
- V2 runs in parallel
- V2 results logged to `.breakpoint/shadow_comparison/`
- V2 does NOT affect final report
- Comparison metrics collected

### Promotion Criteria
- **10-20 scan comparisons** with:
  - Detection parity ≥ 95%
  - False positive rate ≤ V1
  - No critical regressions

---

## Next Steps

1. Implement shadow mode infrastructure
2. Run integration validation suite
3. Collect comparison data
4. Analyze and promote V2 to primary

---

*Updated: 2026-02-15*
