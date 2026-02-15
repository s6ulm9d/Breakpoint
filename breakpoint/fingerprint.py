import re
from typing import Dict, List, Set
from .http_client import HttpClient

class TechFingerprinter:
    """
    Identifies the technology stack (Frameworks, Languages, Servers) 
    to prioritize and tailor attack payloads.
    """
    
    PATTERNS = {
        "PHP": [r"X-Powered-By: PHP", r"\.php", r"PHPSESSID"],
        "Python/Django": [r"csrftoken", r"__import__", r"django"],
        "Python/Flask": [r"session=", r"flask"],
        "Java/Spring": [r"JSESSIONID", r"X-Application-Context", r"Spring"],
        "Node.js": [r"connect\.sid", r"X-Powered-By: Express"],
        "ASP.NET": [r"ASPSESSIONID", r"X-AspNet-Version", r"\.aspx"],
        "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc\.php"],
        "React/Next.js": [r"_next/static", r"__NEXT_DATA__"],
        "Vue.js": [r"v-cloak", r"vue\.js"],
        "Nginx": [r"Server: nginx"],
        "Apache": [r"Server: Apache"],
        "Cloudflare": [r"cf-ray", r"__cfduid", r"Server: cloudflare"],
    }

    def __init__(self, client: HttpClient):
        self.client = client
        self.found_tech: Set[str] = set()

    def identify(self, url: str) -> Set[str]:
        """Performs a fast check on headers and body to detect tech stack."""
        try:
            resp = self.client.send("GET", url)
            headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body = resp.text
            
            combined = headers_str + "\n\n" + body
            
            for tech, regexes in self.PATTERNS.items():
                for regex in regexes:
                    if re.search(regex, combined, re.IGNORECASE):
                        self.found_tech.add(tech)
                        break
                        
            return self.found_tech
        except:
            return set()
