import re
import urllib.parse
import threading
from typing import Set, List, Dict
from bs4 import BeautifulSoup
from .http_client import HttpClient

class Crawler:
    """
    Recursive crawler to discover endpoints, parameters, and forms
    while strictly enforcing domain scope.
    """
    def __init__(self, base_url: str, client: HttpClient, max_depth: int = 3, max_urls: int = 1000):
        self.base_url = base_url.rstrip('/')
        self.domain = urllib.parse.urlparse(base_url).netloc
        self.client = client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: Set[str] = set()
        self.content_hashes: Set[str] = set() # Loop detection for different URLs with same content
        self.discovered_urls: Set[str] = {self.base_url}
        self.forms: List[Dict] = []
        self.lock = threading.Lock()

    def is_in_scope(self, url: str) -> bool:
        """Enforces that the URL belongs to the target domain."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.domain or not parsed.netloc

    def normalize_url(self, url: str, current_page: str) -> str:
        """Joins relative paths and removes fragments."""
        joined = urllib.parse.urljoin(current_page, url)
        return joined.split('#')[0].rstrip('/')

    def crawl(self, url: str = None, depth: int = 0):
        """Recursively discovers links and forms with safety checks."""
        if depth > self.max_depth or len(self.visited) >= self.max_urls: return
        target = url or self.base_url
        
        with self.lock:
            if target in self.visited: return
            self.visited.add(target)
        
        try:
            resp = self.client.send("GET", target)
            if resp.status_code != 200: return
            
            # Content-based loop detection (SPAs often serve same skeleton on many paths)
            import hashlib
            body_hash = hashlib.md5(resp.text[:5000].encode()).hexdigest()
            with self.lock:
                if body_hash in self.content_hashes: return
                self.content_hashes.add(body_hash)

            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # 1. Discover Links
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = self.normalize_url(href, target)
                if self.is_in_scope(full_url) and full_url not in self.discovered_urls:
                    self.discovered_urls.add(full_url)
                    self.crawl(full_url, depth + 1)
            
            # 2. Discover Forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = [i.get('name') for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')]
                self.forms.append({
                    "url": target,
                    "action": self.normalize_url(action, target),
                    "method": method,
                    "fields": inputs
                })
                
        except Exception:
            pass

    def get_scan_targets(self) -> List[Dict]:
        """Returns a list of unique URLs and forms found."""
        targets = []
        # Add pure GET URLs
        for url in self.discovered_urls:
            targets.append({"url": url, "method": "GET", "fields": []})
        # Add Forms
        for form in self.forms:
            targets.append({
                "url": form["action"],
                "method": form["method"].upper(),
                "fields": form["fields"]
            })
        return targets
