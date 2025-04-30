import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests, html, urllib, json, asyncio
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from playwright.async_api import async_playwright

init(autoreset=True)

# Argument Parser
def get_args():
    parser = argparse.ArgumentParser(description="GainXSS - Fast XSS Scanner")
    parser.add_argument("-url", help="Target URL (e.g: http://example.com/search?q=)", required=True)
    parser.add_argument("-p", "--payloads", help="File with XSS payloads", default="payloads.txt")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("--param", help="Parameter name to inject payloads into (default: q)", default="q")
    parser.add_argument("--headers", help="File with custom headers", default=None)
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds (default: 5)", default=5)
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--encode", help="Encode payloads (default: False)", action="store_true")
    parser.add_argument("--verbose", help="Enable verbose output (default: False)", action="store_true")
    parser.add_argument("--output", help="Save output to JSON file", default=None)
    parser.add_argument("--verify-dom", help="Enable DOM-based validation using Playwright", action="store_true")
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

def load_headers(file_path):
    if not file_path:
        return None
    headers = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                key, value = line.strip().split(":", 1)
                headers[key.strip()] = value.strip()
    return headers

def encode_payload(payload):
    return urllib.parse.quote(payload)

def inject_payload(url, param, payload, encode=False):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    query[param] = [encode_payload(payload) if encode else payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed_url._replace(query=new_query))

def is_reflected_in_unsafe_context(response_text, payload):
    soup = BeautifulSoup(response_text, "html.parser")
    encoded = encode_payload(payload)
    escaped = html.escape(payload)

    # Check common vulnerable contexts
    for tag in soup.find_all():
        # Check attribute injection
        for attr_val in tag.attrs.values():
            if isinstance(attr_val, list):
                if any(payload in v or escaped in v or encoded in v for v in attr_val):
                    return True
            elif payload in str(attr_val) or escaped in str(attr_val) or encoded in str(attr_val):
                return True

        # Check content inside script tags
        if tag.name == "script" and payload in tag.text:
            return True

        # Check inner text of tags
        if payload in tag.text or escaped in tag.text:
            return True

    return False

def init_session(headers=None, proxy=None):
    session = requests.Session()
    session.headers.update(headers or {})
    session.proxies = {"http": proxy, "https": proxy} if proxy else None
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

async def verify_in_browser(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=10000)
            await asyncio.sleep(2)
            dialog_triggered = False

            async def on_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", on_dialog)
            await asyncio.sleep(1)
            return dialog_triggered
        except Exception as e:
            return False
        finally:
            await browser.close()

def check_xss(url, payloads, param, headers=None, timeout=5, proxy=None, encode=False, verbose=False, max_workers=50, verify_dom=False):
    vulnerable = []
    session = init_session(headers, proxy)

    def test_payload(payload):
        test_url = inject_payload(url, param, payload, encode)
        try:
            response = session.get(test_url, timeout=timeout)
            if is_reflected_in_unsafe_context(response.text, payload):
                result = {"url": test_url, "payload": payload, "confirmed": False}
                if verbose:
                    print(Fore.GREEN + f"[+] Reflection in unsafe context: {test_url}")
                return result
            elif verbose:
                print(Fore.LIGHTBLACK_EX + f"[-] Not vulnerable (safe context): {test_url}")
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

    if verify_dom:
        print(Fore.CYAN + "\n[+] Verifying potential XSS in browser context...\n")
        loop = asyncio.get_event_loop()
        for vuln in vulnerable:
            confirmed = loop.run_until_complete(verify_in_browser(vuln["url"]))
            vuln["confirmed"] = confirmed
            if confirmed:
                print(Fore.RED + f"[!] Confirmed DOM Execution: {vuln['url']}")

    return vulnerable

def print_results(results):
    print("\n" + "-"*40)
    if results:
        print(Fore.RED + "[!] XSS Vulnerabilities Found:\n")
        for item in results:
            print(Fore.YELLOW + f"URL: {item['url']}")
            print(Fore.GREEN + f"Payload: {item['payload']}")
            print(Fore.RED + f"Confirmed: {item['confirmed']}\n")
    else:
        print(Fore.GREEN + "[✓] No XSS vulnerabilities found.")
    print("-"*40)

def save_results(results, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(Fore.CYAN + f"[+] Results saved to {path}")
    except Exception as e:
        print(Fore.RED + f"[!] Could not save results: {e}")

def main():
    args = get_args()
    payloads = load_payloads(args.payloads)
    headers = load_headers(args.headers)
    results = check_xss(
        args.url,
        payloads,
        param=args.param,
        headers=headers,
        timeout=args.timeout,
        proxy=args.proxy,
        encode=args.encode,
        verbose=args.verbose,
        max_workers=args.threads,
        verify_dom=args.verify_dom
    )
    print_results(results)
    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    main()
