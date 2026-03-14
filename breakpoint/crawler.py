import re
import urllib.parse
import threading
from typing import Set, List, Dict
from bs4 import BeautifulSoup
from .http_client import HttpClient

class Crawler:
    """
    Enhanced recursive crawler to discover endpoints, parameters, and forms.
    Features: robes.txt parsing, sitemap discovery, JS route extraction, and path fuzzing.
    """
    COMMON_SENSITIVE_PATHS = [
        "/.env", "/.git/config", "/admin", "/debug", "/actuator/health", "/api/v1/users",
        "/config.json", "/phpinfo.php", "/wp-config.php", "/.htaccess", "/backup.zip"
    ]

    def __init__(self, base_url: str, client: HttpClient, max_depth: int = 3, max_urls: int = 1000):
        self.base_url = base_url.rstrip('/')
        self.domain = urllib.parse.urlparse(base_url).netloc
        self.client = client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: Set[str] = set()
        self.content_hashes: Set[str] = set()
        self.discovered_urls: Set[str] = {self.base_url}
        self.forms: List[Dict] = []
        self.js_routes: Set[str] = set()
        self.lock = threading.Lock()

    def is_in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.domain or not parsed.netloc

    def normalize_url(self, url: str, current_page: str) -> str:
        joined = urllib.parse.urljoin(current_page, url)
        return joined.split('#')[0].rstrip('/')

    def crawl(self):
        """Main orchestrator for discovery."""
        # 1. Start with robots.txt and sitemaps
        self._discover_from_meta()
        
        # 2. Basic sensitive path fuzzing
        self._fuzz_sensitive_paths()

        # 3. Recursive crawling starting from base
        self._recursive_crawl(self.base_url, 0)

    def _discover_from_meta(self):
        """Parses robots.txt and sitemap.xml."""
        # robots.txt
        try:
            resp = self.client.send("GET", f"{self.base_url}/robots.txt", timeout=5)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if "disallow:" in line.lower() or "allow:" in line.lower():
                        path = line.split(":", 1)[1].strip()
                        if path and "*" not in path:
                            full_url = self.normalize_url(path, self.base_url)
                            if self.is_in_scope(full_url): self.discovered_urls.add(full_url)
        except: pass

        # sitemap.xml (simple version)
        try:
            resp = self.client.send("GET", f"{self.base_url}/sitemap.xml", timeout=5)
            if resp.status_code == 200:
                urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
                for url in urls:
                    if self.is_in_scope(url): self.discovered_urls.add(url)
        except: pass

    def _fuzz_sensitive_paths(self):
        """Checks for common sensitive endpoints."""
        for path in self.COMMON_SENSITIVE_PATHS:
            try:
                full_url = self.base_url + path
                resp = self.client.send("HEAD", full_url, timeout=2)
                if resp.status_code in [200, 403, 401]:
                    self.discovered_urls.add(full_url)
            except: pass

    def _recursive_crawl(self, url: str, depth: int):
        if depth > self.max_depth or len(self.visited) >= self.max_urls: return
        
        with self.lock:
            if url in self.visited: return
            self.visited.add(url)
        
        try:
            resp = self.client.send("GET", url)
            if resp.status_code != 200: return
            
            import hashlib
            body_hash = hashlib.md5(resp.text[:5000].encode()).hexdigest()
            with self.lock:
                if body_hash in self.content_hashes: return
                self.content_hashes.add(body_hash)

            # 1. Handle JSON Content
            content_type = resp.headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                try:
                    import json
                    data = json.loads(resp.text)
                    self._extract_from_json(data, url)
                except: pass
                return # Skip HTML parsing for JSON

            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # 1. Discover Links
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = self.normalize_url(href, url)
                if self.is_in_scope(full_url) and full_url not in self.discovered_urls:
                    self.discovered_urls.add(full_url)
                    self._recursive_crawl(full_url, depth + 1)
            
            # 2. Discover Forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = [i.get('name') for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')]
                self.forms.append({
                    "url": url,
                    "action": self.normalize_url(action, url),
                    "method": method,
                    "fields": inputs
                })
            
            # 3. Discovery from JS files
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_src = self.normalize_url(src, url)
                if self.is_in_scope(full_src):
                    self._extract_routes_from_js(full_src)
            
            # 4. Next.js Specific: Parse __NEXT_DATA__
            next_data = soup.find('script', id='__NEXT_DATA__')
            if next_data and next_data.string:
                self._extract_from_next_data(next_data.string)
                
        except Exception: pass

    def _extract_from_json(self, data: any, source_url: str):
        """Recursively discover paths in JSON payloads."""
        if isinstance(data, str):
            # Check if string looks like a path or URL
            if data.startswith('/') or data.startswith('http') or '.php' in data or '.html' in data:
                full_url = self.normalize_url(data, source_url)
                if self.is_in_scope(full_url) and full_url not in self.discovered_urls:
                    self.discovered_urls.add(full_url)
                    # We don't recurse on discovered JSON strings to avoid over-crawling
        elif isinstance(data, dict):
            for v in data.values():
                self._extract_from_json(v, source_url)
        elif isinstance(data, list):
            for item in data:
                self._extract_from_json(item, source_url)

    def _extract_from_next_data(self, json_str: str):
        """Extracts routes and pre-fetched data from Next.js hydration payload."""
        import json
        try:
            data = json.loads(json_str)
            # 1. Page routes
            page = data.get('page', '')
            if page and not page.startswith('/_'):
                self.discovered_urls.add(self.base_url + page)
        except: pass

    def _extract_routes_from_js(self, js_url: str):
        """Regex-based endpoint extraction from JS files."""
        try:
            resp = self.client.send("GET", js_url, timeout=5)
            if resp.status_code == 200:
                # Look for patterns like "/api/v1/..." or "path: '/...'"
                patterns = [
                    r'["\'](/api/[\w/-]+)["\']',
                    r'path:\s*["\'](/[\w/-]+)["\']',
                    r'url:\s*["\'](/[\w/-]+)["\']'
                ]
                for p in patterns:
                    matches = re.findall(p, resp.text)
                    for m in matches:
                        full_url = self.base_url + m
                        if full_url not in self.discovered_urls:
                             self.discovered_urls.add(full_url)
        except: pass

    def get_scan_targets(self) -> List[Dict]:
        targets = []
        for url in self.discovered_urls:
            targets.append({"url": url, "method": "GET", "fields": []})
        for form in self.forms:
            targets.append({
                "url": form["action"],
                "method": form["method"].upper(),
                "fields": form["fields"]
            })
        return targets
