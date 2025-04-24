import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import html , urllib


init(autoreset=True)

#Argument Parser
def get_args():
    parser = argparse.ArgumentParser(description="GainXSS - Fast XSS Scanner")
    parser.add_argument("-url", help="Target URL (e.g: http://example.com/search?q=)", required=True)
    parser.add_argument("-p", "--payloads", help="File with XSS payloads", default="payloads.txt")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    return parser.parse_args()

def load_payloads(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {file_path}")
        exit(1)
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied: {file_path}")
        exit(1)

def inject_payload(url, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    for param, value in query.items():
        if param not in ["q", "query", "search"]:  # Add more common parameter names here
            query[param] = payload
            break
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed_url._replace(query=new_query))

def is_reflected(response_text, payload):
    return payload in response_text or html.escape(payload) in response_text or urllib.parse.quote(payload) in response_text

def check_xss(url, payloads, max_workers=50):
    vulnerable = []
    session = requests.Session()

    def test_payload(payload):
        test_url = inject_payload(url, payload)
        try:
            response = session.get(test_url, timeout=5)
            if is_reflected(response.text, payload):
                return (test_url, payload)
        except Exception as e:
            print(Fore.LIGHTBLACK_EX + f"[!] Error with payload: {payload[:30]}... -> {e}")
        return None

    print(Fore.CYAN + f"\n[+] Scanning with {len(payloads)} payloads using {max_workers} threads...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_payload, payload) for payload in payloads]
        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerable.append(result)

    return vulnerable

def print_results(results):
    print("\n" + "-"*40)
    if results:
        print(Fore.RED + "[!] XSS Vulnerabilities Found:\n")
        for url, payload in results:
            print(Fore.YELLOW + f"URL: {url}")
            print(Fore.GREEN + f"Payload: {payload}\n")
    else:
        print(Fore.GREEN + "[✓] No XSS vulnerabilities found.")
    print("-"*40)

# Main entry
def main():
    args = get_args()
    payloads = load_payloads(args.payloads)
    results = check_xss(args.url, payloads, max_workers=args.threads)
    print_results(results)

if __name__ == "__main__":
    main()