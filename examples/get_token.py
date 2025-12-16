import requests
import argparse
import sys
from colorama import Fore, Style, init

def get_auth_token(target_url, username, password, method="POST", json_body=True):
    """
    Helper to attempt login and retrieve Auth Token or Session Cookie.
    """
    init(autoreset=True)
    
    login_url = target_url.rstrip('/') + "/api/auth/login" # Adjust based on typical paths or argument
    # If user provides full URL, use it
    if "login" in target_url or "signin" in target_url:
        login_url = target_url
        
    print(f"[*] Attempting login at: {login_url}")
    
    payload = {"email": username, "password": password}
    if not json_body:
        # Form data
        data = payload
        json_data = None
    else:
        # JSON
        data = None
        json_data = payload
        
    try:
        if json_body:
            resp = requests.post(login_url, json=payload, timeout=10)
        else:
            resp = requests.post(login_url, data=payload, timeout=10)
            
        print(f"[*] Status: {resp.status_code}")
        
        if resp.status_code == 200:
            print(f"{Fore.GREEN}[+] Login Successful!{Style.RESET_ALL}")
            
            # 1. Check for Token in Response Body (JSON)
            try:
                data = resp.json()
                token = data.get("token") or data.get("access_token") or data.get("jwt")
                if token:
                    print(f"\n{Fore.CYAN}[FOUND] Authorization Token (Bearer):{Style.RESET_ALL}")
                    print(f"Authorization: Bearer {token}")
                    print("\nCopy the above line and pass it to --headers")
                    return
            except:
                pass
                
            # 2. Check for Cookies (Session ID)
            if resp.cookies:
                print(f"\n{Fore.CYAN}[FOUND] Session Cookies:{Style.RESET_ALL}")
                cookie_str = "; ".join([f"{k}={v}" for k, v in resp.cookies.items()])
                print(f"Cookie: {cookie_str}")
                print("\nCopy the above line and pass it to --headers")
                return
                
            # 3. Check for Headers (Authorization)
            auth_header = resp.headers.get("Authorization")
            if auth_header:
                print(f"\n{Fore.CYAN}[FOUND] Authorization Header:{Style.RESET_ALL}")
                print(f"Authorization: {auth_header}")
                return
                
            print(f"{Fore.YELLOW}[!] Could not automatically extract token. Please check response manually.{Style.RESET_ALL}")
            print(resp.text[:500])
            
        else:
            print(f"{Fore.RED}[-] Login Failed.{Style.RESET_ALL}")
            print(resp.text[:200])
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quick Auth Token Fetcher")
    parser.add_argument("url", help="Target Login URL (e.g. http://localhost:3000/api/login)")
    parser.add_argument("-u", "--username", required=True, help="Username/Email")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--form", action="store_true", help="Send as Form Data instead of JSON")
    
    args = parser.parse_args()
    
    get_auth_token(args.url, args.username, args.password, json_body=not args.form)
