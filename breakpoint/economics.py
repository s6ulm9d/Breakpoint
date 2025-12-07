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
            if not r.get("passed"):
                # Compromise Costs (Data Breach estimation)
                # Ponemon Institute avg: $160 per record. We assume 10k records exposed per Critical.
                sev = r.get("meta", {}).get("severity", "LOW")
                if sev == "CRITICAL":
                    criticals += 1
                    self.compromise_cost += 150000.0 # Flat fee for critical breach
                elif sev == "HIGH":
                    highs += 1
                    self.compromise_cost += 50000.0

            # Latency / Downtime calc
            # If an attack caused the server to hang or error 500 significantly
            details = r.get("details", {})
            if isinstance(details, dict):
                issues = details.get("issues", [])
                for i in issues:
                    if "500" in str(i) or "Crash" in str(i):
                        self.downtime_minutes += 5.0 # Assume 5 min recovery per crash event
                    if "Lagged" in str(i) or "Slow" in str(i):
                        # Approximate lag
                        self.latency_penalty += (self.rpm * 0.1) # 10% rev loss during degradation

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
