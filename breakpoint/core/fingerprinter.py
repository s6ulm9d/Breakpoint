"""
Automatic Tech Fingerprinting Engine
Analyzes headers, response signatures, and framework artifacts to build TargetContext.
"""
from typing import Dict, Set, List, Optional
import re
from ..http_client import ResponseWrapper
from .context import TargetContext

class TechFingerprinter:
    """
    Automatic technology detection via passive and active fingerprinting.
    Populates TargetContext with detected tech stack using a confidence-based scoring system.
    """
    
    # Header-based signatures with confidence weights
    HEADER_SIGNATURES = {
        # tech: {header_name: ([patterns], confidence_weight)}
        "nginx": {"server": (["nginx"], 0.7)},
        "apache": {"server": (["apache"], 0.7)},
        "iis": {"server": (["microsoft-iis"], 0.8)},
        "cloudflare": {"server": (["cloudflare"], 0.9)},
        
        "express": {"x-powered-by": (["express"], 0.6)},
        "django": {"server": (["wsgiserver"], 0.4), "x-frame-options": (["deny", "sameorigin"], 0.1)},
        "flask": {"server": (["werkzeug", "gunicorn"], 0.3)},
        "rails": {"x-powered-by": (["phusion passenger"], 0.8)},
        "asp.net": {"x-powered-by": (["asp.net"], 0.8), "x-aspnet-version": (["*"], 0.4)},
        "next.js": {"x-powered-by": (["next.js"], 0.9)},
        "php": {"x-powered-by": (["php"], 0.8), "set-cookie": (["phpsessid"], 0.6)},
        "java": {"set-cookie": (["jsessionid"], 0.7)},
    }
    
    # Response body signatures with confidence weights
    BODY_SIGNATURES = {
        "react": ([r'<div id="root"', r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'react-dom'], 0.5),
        "vue": ([r'<div id="app"', r'vue\.js', r'data-v-[a-f0-9]+', r'__VUE_HOT_MAP__'], 0.5),
        "angular": ([r'ng-version', r'angular', r'<app-root', r'ng-app'], 0.5),
        "next.js": ([r'__NEXT_DATA__', r'_next/static', r'/_next/image'], 0.7),
        "nuxt": ([r'__NUXT__'], 0.7),
        "wordpress": ([r'wp-content', r'wp-includes', r'wp-json', r'WordPress'], 0.8),
        "drupal": ([r'Drupal', r'sites/default', r'Drupal.settings'], 0.8),
        "jquery": ([r'jquery\.min\.js', r'jquery-[0-9\.]+\.js'], 0.3),
        "bootstrap": ([r'bootstrap\.min\.css', r'bootstrap\.min\.js'], 0.3),
    }

    # Active probing with high confidence weights (Confirmed status)
    PROBE_SIGNATURES = {
        # tech: {path: (status_code, [content_patterns], confidence)}
        "django": ("/admin/login/?next=/admin/", 200, ["django"], 0.9),
        "rails": ("/rails/info/routes", 200, ["Routes"], 1.0),
        "laravel": ("/_debugbar/open", 200, ["PHPDebugBar"], 1.0),
        "spring": ("/actuator/health", 200, ["UP", "status"], 1.0),
        "next.js": ("/_next/static/chunks/main.js", 200, [], 0.9),
        "swagger": ("/v2/api-docs", 200, ["swagger", "definitions"], 1.0),
        "graphql": ("/graphql", 400, ["Must provide query"], 0.8),
    }
    
    def __init__(self, client):
        self.client = client
        self.scores: Dict[str, float] = {}
    
    def fingerprint(self, target_url: str, context: TargetContext) -> TargetContext:
        baseline_response = self.client.send("GET", target_url)
        self._analyze_headers(baseline_response)
        self._analyze_body(baseline_response)
        self._active_probe(target_url)
        
        # 3. Resolve conflicts and filter
        self._resolve_conflicts()
        
        # 4. Update context and infer DB
        for tech, score in self.scores.items():
            key = self._get_category(tech)
            context.update_tech_stack(key, tech, confidence=score)
            
        self._infer_database(context)
        return context
    
    def _analyze_headers(self, response: ResponseWrapper):
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        for tech, sig_map in self.HEADER_SIGNATURES.items():
            total_weight = 0.0
            for header_name, (patterns, weight) in sig_map.items():
                if header_name in headers_lower:
                    val = headers_lower[header_name]
                    if any(p == "*" or p in val for p in patterns):
                        total_weight += weight
            if total_weight > 0:
                self.scores[tech] = self.scores.get(tech, 0.0) + total_weight

    def _analyze_body(self, response: ResponseWrapper):
        body = response.text.lower()
        for tech, (patterns, weight) in self.BODY_SIGNATURES.items():
            if any(re.search(p, body, re.IGNORECASE) for p in patterns):
                self.scores[tech] = self.scores.get(tech, 0.0) + weight

    def _active_probe(self, target_url: str):
        """Perform active probing for framework-specific routes."""
        for tech, (path, expected_status, patterns, weight) in self.PROBE_SIGNATURES.items():
            try:
                probe_url = target_url.rstrip('/') + path
                resp = self.client.send("GET", probe_url)
                
                # Check status code and optional body patterns
                if resp.status_code == expected_status:
                    if not patterns or any(p.lower() in resp.text.lower() for p in patterns):
                        self.scores[tech] = self.scores.get(tech, 0.0) + weight
            except: pass

    def _resolve_conflicts(self):
        """Prevents reporting multiple mutually exclusive frameworks."""
        # Normalize scores to 1.0
        for tech in self.scores:
            self.scores[tech] = min(self.scores[tech], 1.0)
            
        CONFLICT_GROUPS = [
            ["django", "rails", "spring", "laravel", "express", "next.js", "wordpress", "drupal"],
            ["react", "vue", "angular"]
        ]
        
        for group in CONFLICT_GROUPS:
            detected_in_group = [t for t in group if t in self.scores]
            if len(detected_in_group) > 1:
                # Keep only the one with the highest score
                best_tech = max(detected_in_group, key=lambda t: self.scores[t])
                for t in detected_in_group:
                    if t != best_tech:
                        # If the absolute difference is small, maybe it's a hybrid (like Next.js + Rails)?
                        # But for now, we follow the user's advice: don't report all simultaneously.
                        # We penalize the low confidence one heavily if a strong winner exists.
                        if self.scores[best_tech] > self.scores[t] * 1.5:
                             del self.scores[t]

    def _get_category(self, tech: str) -> str:
        servers = ["nginx", "apache", "iis", "cloudflare"]
        languages = ["php", "python", "java", "javascript"]
        if tech in servers: return "server"
        if tech in languages: return "language"
        return "framework"

    def _infer_database(self, context: TargetContext):
        frameworks = context.tech_stack.frameworks
        if "django" in frameworks or "rails" in frameworks:
            context.update_tech_stack("database", "Postgres", confidence=0.7)
        if "php" in context.tech_stack.languages or "wordpress" in frameworks:
            context.update_tech_stack("database", "MySQL", confidence=0.7)
        if "spring" in frameworks:
            context.update_tech_stack("database", "MySQL", confidence=0.5)
        if "express" in frameworks or "next.js" in frameworks:
            context.update_tech_stack("database", "MongoDB", confidence=0.5)
