import re
import time
from typing import List, Dict, Optional, Set, Tuple, Any, TYPE_CHECKING
import bs4
import os

def create_folder(path: str):
    """Utility to create a folder if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)

class StructuralComparator:
    """
    Advanced response comparison that looks at structural changes (DOM, headers)
    rather than just raw text length.
    """
    
    @staticmethod
    def get_structure(html: str) -> Dict[str, Any]:
        """Extracts structural fingerprint of a page."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return {
                "tags": [tag.name for tag in soup.find_all(True)],
                "tag_counts": {tag: len(soup.find_all(tag)) for tag in set([t.name for t in soup.find_all(True)])},
                "inputs": [i.get('name') or i.get('id') for i in soup.find_all('input')],
                "scripts": len(soup.find_all('script')),
                "title": soup.title.string.strip() if soup.title else ""
            }
        except:
            return {"tags": [], "tag_counts": {}, "inputs": [], "scripts": 0, "title": ""}

    @staticmethod
    def is_significant_delta(base_html: str, current_html: str) -> bool:
        """Determines if the structural delta is large enough to indicate success (e.g. IDOR/NoSQL)."""
        base = StructuralComparator.get_structure(base_html)
        curr = StructuralComparator.get_structure(current_html)
        
        # 1. Check title change
        if base["title"] != curr["title"] and curr["title"]:
            return True
            
        # 2. Check input field changes (Discovery of new forms)
        if set(base["inputs"]) != set(curr["inputs"]):
            return True
            
        # 3. Check tag count variance (Structural shift)
        if abs(len(base["tags"]) - len(curr["tags"])) > 20:
            return True
            
        return False

def extract_reflection_context(html: str, canary: str) -> str:
    """Identifies the HTML context of a reflected string (Attribute, Script, Text)."""
    if canary not in html:
        return "none"
    
    # 1. Check Script Context
    script_regex = rf"<script[^>]*>.*{re.escape(canary)}.*</script>"
    if re.search(script_regex, html, re.DOTALL | re.IGNORECASE):
        return "script"
        
    # 2. Check Attribute Context
    attr_regex = rf"=['\"][^'\"]*{re.escape(canary)}[^'\"]*['\"]"
    if re.search(attr_regex, html, re.IGNORECASE):
        return "attribute"
        
    # 3. Check Tag Name Context (Dangerous)
    tag_regex = rf"<{re.escape(canary)}[^>]*>"
    if re.search(tag_regex, html, re.IGNORECASE):
        return "tag"
        
    return "text"

class ResponseStabilizer:
    """
    Computes stability of a page by comparing multiple baseline samples.
    Identifies dynamic regions (timestamps, random IDs) to avoid false positives.
    """
    @staticmethod
    def get_variance_mask(client: Any, method: str, url: str, params: Dict = None, body: Dict = None) -> Set[int]:
        """Sends 3 requests and returns a set of indices where the response text varies."""
        from breakpoint.http_client import HttpClient
        samples = []
        for _ in range(3):
            # Pass HttpClient and Scenario info to send
            resp = client.send(method, url, params=params, json_body=body, is_canary=True)
            samples.append(resp.text)
            time.sleep(0.1)
            
        if not samples: return set()
        
        variance_indices = set()
        # Find characters that change across samples
        min_len = min(len(s) for s in samples)
        for i in range(min_len):
            if any(samples[j][i] != samples[0][i] for j in range(len(samples))):
                variance_indices.add(i)
        return variance_indices

    @staticmethod
    def normalize(text: str, mask: Set[int]) -> str:
        """Replaces variant characters with a placeholder to allow stable comparison."""
        chars = list(text)
        for i in mask:
            if i < len(chars):
                chars[i] = '*'
        return "".join(chars)
