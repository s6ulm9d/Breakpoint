from typing import List, Dict

class FailureEconomics:
    """
    Calculates the financial impact of detected vulnerabilities and outages.
    "If this happened in prod, how much would we bleed?"
    """
    def __init__(self, revenue_per_minute: float = 1000.0, slo_latency_ms: float = 200.0):
        self.rpm = revenue_per_minute
        self.slo_ms = slo_latency_ms
        self.downtime_minutes = 0.0
        self.latency_penalty = 0.0
        self.compromise_cost = 0.0

    def calculate_impact(self, results: List[Dict]):
        criticals = 0
        highs = 0
        total_latency_breach_ms = 0
        
        for r in results:
            # Handle dataclass or dict
            passed = r.status in ["SECURE", "PASSED"] if hasattr(r, 'status') else r.get("passed")
            severity = r.severity if hasattr(r, 'severity') else r.get("meta", {}).get("severity", "LOW")
            details_text = r.details if hasattr(r, 'details') else r.get("details", "")

            if not passed:
                # Compromise Costs (Data Breach estimation)
                if severity == "CRITICAL":
                    criticals += 1
                    # RCE / CVEs often permit full DB dumps or ransomware
                    check_type = r.type if hasattr(r, 'type') else r.get("attack_type", "")
                    if check_type in ["rce", "cve_log4shell", "cve_spring4shell", "cve_struts2"]:
                         self.compromise_cost += 500000.0 # Full Compromise / Ransomware Risk
                    else:
                         self.compromise_cost += 150000.0 # Data Breach (SQLi, XXE)
                         
                elif severity == "HIGH":
                    highs += 1
                    self.compromise_cost += 50000.0

            # --- Downtime & Outage Calculation (Refined) ---
            check_type = r.type if hasattr(r, 'type') else r.get("attack_type", "")
            
            # 1. Successful DoS (Service Unavailable)
            if check_type in ["dos_extreme", "slowloris", "advanced_dos"] and not passed:
                 # If DoS succeeded, effectively taking down the service. 
                 # Assume MTTR (Mean Time To Recovery) involves detection + mitigation.
                 self.downtime_minutes += 20.0 
            
            # 2. Server Crashes / Hangs (RCE or Destructive Payloads)
            elif ("Crash" in str(details_text) or "Hang" in str(details_text)) and not passed:
                 # Server crashed physically or process died. Restart req.
                 self.downtime_minutes += 10.0
                 
            # 3. Latency Degradation (ReDoS, Time-Based SQLi)
            elif "delayed" in str(details_text) or "timeout" in str(details_text).lower():
                 # 50% revenue hit for slight degradation detected
                 self.latency_penalty += (self.rpm * 0.5) 


        # Outage Cost
        outage_cost = self.downtime_minutes * self.rpm
        
        total_liability = self.compromise_cost + outage_cost + self.latency_penalty
        
        return {
            "downtime_minutes": self.downtime_minutes,
            "outage_cost": f"${outage_cost:,.2f}",
            "compromise_liability": f"${self.compromise_cost:,.2f}",
            "latency_penalty": f"${self.latency_penalty:,.2f}",
            "total_estimated_damage": f"${total_liability:,.2f}"
        }
