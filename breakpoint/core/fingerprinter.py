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
    Populates TargetContext with detected tech stack.
    """
    
    # Header-based signatures
    HEADER_SIGNATURES = {
        # Web Servers
        "nginx": {"server": ["nginx"]},
        "apache": {"server": ["apache"]},
        "iis": {"server": ["microsoft-iis"]},
        "cloudflare": {"server": ["cloudflare"]},
        
        # Frameworks
        "express": {"x-powered-by": ["express"]},
        "django": {"server": ["wsgiserver"], "x-frame-options": ["deny", "sameorigin"]},
        "flask": {"server": ["werkzeug", "gunicorn"]},
        "rails": {"x-powered-by": ["phusion passenger"]},
        "asp.net": {"x-powered-by": ["asp.net"], "x-aspnet-version": ["*"]},
        "next.js": {"x-powered-by": ["next.js"]},
        
        # Languages
        "php": {"x-powered-by": ["php"], "set-cookie": ["phpsessid"]},
        "java": {"set-cookie": ["jsessionid"]},
        "python": {"server": ["python", "gunicorn", "uwsgi"]},
        
        # Databases (indirect)
        "postgres": {"x-powered-by": ["postgrest"]},
    }
    
    # Response body signatures
    BODY_SIGNATURES = {
        "react": [
            r'<div id="root"',
            r'react',
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
        ],
        "vue": [
            r'<div id="app"',
            r'vue\.js',
            r'data-v-[a-f0-9]+',
        ],
        "angular": [
            r'ng-version',
            r'angular',
            r'<app-root',
        ],
        "next.js": [
            r'__NEXT_DATA__',
            r'_next/static',
        ],
        "wordpress": [
            r'wp-content',
            r'wp-includes',
            r'WordPress',
        ],
        "drupal": [
            r'Drupal',
            r'sites/default',
        ],
    }
    
    # Framework-specific endpoints (active probing)
    PROBE_ENDPOINTS = {
        "django": ["/__debug__/", "/admin/"],
        "rails": ["/rails/info/routes"],
        "laravel": ["/telescope", "/horizon"],
        "spring": ["/actuator/health", "/actuator/info"],
        "graphql": ["/graphql", "/api/graphql"],
        "swagger": ["/swagger-ui.html", "/api/docs", "/v2/api-docs"],
    }
    
    def __init__(self, client):
        self.client = client
        self.detected_tech: Set[str] = set()
    
    def fingerprint(self, target_url: str, context: TargetContext) -> TargetContext:
        """
        Main fingerprinting orchestrator.
        Returns enriched TargetContext.
        """
        # 1. Passive fingerprinting (headers + body)
        baseline_response = self.client.send("GET", target_url)
        self._analyze_headers(baseline_response, context)
        self._analyze_body(baseline_response, context)
        
        # 2. Active probing (framework-specific endpoints)
        self._active_probe(target_url, context)
        
        # 3. Infer database from framework
        self._infer_database(context)
        
        return context
    
    def _analyze_headers(self, response: ResponseWrapper, context: TargetContext):
        """
        Passive header analysis.
        Logic:
        - Iterate through HEADER_SIGNATURES
        - Check if response headers match signature patterns
        - Update context.tech_stack
        """
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for tech, sig_map in self.HEADER_SIGNATURES.items():
            for header_name, patterns in sig_map.items():
                if header_name in headers_lower:
                    header_value = headers_lower[header_name]
                    
                    for pattern in patterns:
                        if pattern == "*" or pattern in header_value:
                            self._add_tech(tech, context)
                            break
    
    def _analyze_body(self, response: ResponseWrapper, context: TargetContext):
        """
        Passive body signature analysis.
        Logic:
        - Search response body for framework-specific patterns
        - Use regex matching for accuracy
        - Update context.tech_stack
        """
        body = response.text.lower()
        
        for tech, patterns in self.BODY_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_tech(tech, context)
                    break
    
    def _active_probe(self, target_url: str, context: TargetContext):
        """
        Active probing for framework-specific endpoints.
        Logic:
        - Try accessing known framework endpoints
        - If 200/403 (exists but protected), framework is present
        - If 404, framework not present
        - Update context.tech_stack
        """
        for tech, endpoints in self.PROBE_ENDPOINTS.items():
            for endpoint in endpoints:
                try:
                    probe_url = target_url.rstrip('/') + endpoint
                    resp = self.client.send("GET", probe_url)
                    
                    # 200 = endpoint exists, 403 = exists but protected
                    if resp.status_code in [200, 403]:
                        self._add_tech(tech, context)
                        break
                except:
                    # Connection errors = skip
                    pass
    
    def _infer_database(self, context: TargetContext):
        """
        Infer database from detected frameworks.
        Logic:
        - Django/Rails → Postgres likely
        - PHP/WordPress → MySQL likely
        - Spring → MySQL/Postgres
        - Node.js → MongoDB possible
        """
        frameworks = context.tech_stack.frameworks
        
        # Django/Rails → Postgres
        if "django" in frameworks or "rails" in frameworks:
            context.update_tech_stack("database", "Postgres")
        
        # PHP/WordPress → MySQL
        if "php" in context.tech_stack.languages or "wordpress" in frameworks:
            context.update_tech_stack("database", "MySQL")
        
        # Spring → MySQL (common default)
        if "spring" in frameworks:
            context.update_tech_stack("database", "MySQL")
        
        # Express/Next.js → MongoDB possible
        if "express" in frameworks or "next.js" in frameworks:
            context.update_tech_stack("database", "MongoDB")
    
    def _add_tech(self, tech: str, context: TargetContext):
        """
        Helper to add detected tech to context.
        Categorizes into language/framework/server/database.
        """
        # Categorization logic
        servers = ["nginx", "apache", "iis", "cloudflare"]
        languages = ["php", "python", "java", "javascript"]
        frameworks = ["django", "flask", "rails", "express", "next.js", "react", "vue", "angular", "wordpress", "spring"]
        
        if tech in servers:
            context.update_tech_stack("server", tech)
        elif tech in languages:
            context.update_tech_stack("language", tech)
        elif tech in frameworks:
            context.update_tech_stack("framework", tech)
        
        self.detected_tech.add(tech)
