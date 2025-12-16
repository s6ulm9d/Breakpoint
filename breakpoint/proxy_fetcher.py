import requests
import re
from colorama import Fore, Style

def fetch_public_proxies(limit=100):
    """
    Scrapes fresh public HTTP/HTTPS proxies from reliable GitHub lists.
    Fallback for when user provides no proxies.
    """
    print(f"{Fore.CYAN}[*] Auto-fetching fresh public proxies...{Style.RESET_ALL}")
    
    sources = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"
    ]
    
    proxies = set()
    
    for url in sources:
        try:
            print(f"    -> Fetching from {url[:40]}...")
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                        proxies.add(f"http://{line}")
                        if len(proxies) >= limit * 2: # Fetch extra to filter
                            break
        except:
             pass
    
    # Filter/Validation could go here but slows startup. 
    # We rely on HttpClient rotation to discard bad ones.
    
    valid_list = list(proxies)[:limit]
    print(f"{Fore.GREEN}[+] Scraped {len(valid_list)} public proxies for rotation.{Style.RESET_ALL}")
    return valid_list
