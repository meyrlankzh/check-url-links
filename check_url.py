import base64
import os
import time

import requests
from colorama import Fore, init

init(autoreset=True)

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3"

PHISHING_WORDS = ["private key", "wallet", "login", "password",
                  "verify account", "update now"]
MALWARE_INDICATORS = [".exe", ".bat", ".dmg", "miner", "free_bitcoin"]


def local_analysis(url):
    """Download the page and scan its HTML for suspicious keywords."""
    print(f"\n{Fore.BLUE}[*] Running local static analysis...")
    try:
        html = requests.get(url, timeout=5).text.lower()
    except Exception as e:
        print(f"{Fore.RED}[!] Could not read the page: {e}")
        return

    phishing = [w for w in PHISHING_WORDS if w in html]
    malware = [m for m in MALWARE_INDICATORS if m in html]

    print(f"{Fore.CYAN}--- LOCAL ANALYSIS ---")
    if phishing:
        print(f"{Fore.RED}[!] Possible phishing keywords found: {phishing}")
    if malware:
        print(f"{Fore.RED}[!] Possible malware indicators found: {malware}")
    if not phishing and not malware:
        print(f"{Fore.GREEN}[+] No suspicious content found in the page code.")
    print(f"{Fore.CYAN}----------------------")


def virustotal_check(url):
    """Check the URL against the VirusTotal global database."""
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    try:
        r = requests.post(f"{VT_URL}/urls", data={"url": url},
                          headers=headers, timeout=15)
        if r.status_code == 401:
            print(f"{Fore.RED}[!] Invalid VirusTotal API key.")
            return
        r.raise_for_status()

        analysis_id = r.json()["data"]["id"]
        print(f"\n{Fore.YELLOW}[*] Waiting for VirusTotal analysis...")
        for _ in range(6):
            a = requests.get(f"{VT_URL}/analyses/{analysis_id}",
                             headers=headers, timeout=15)
            if a.json()["data"]["attributes"]["status"] == "completed":
                break
            time.sleep(3)

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report = requests.get(f"{VT_URL}/urls/{url_id}",
                              headers=headers, timeout=15)
        if report.status_code != 200:
            print(f"{Fore.RED}[!] Could not get the report. Code: {report.status_code}")
            return

        attrs = report.json()["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        results = attrs["last_analysis_results"]

        print(f"\n{Fore.CYAN}=== VIRUSTOTAL RESULTS ===")
        print(f"{Fore.GREEN}Harmless:   {stats.get('harmless', 0)}")
        print(f"{Fore.WHITE}Suspicious: {stats.get('suspicious', 0)}")
        print(f"{Fore.RED}Malicious:  {stats.get('malicious', 0)}")
        print(f"{Fore.CYAN}==========================\n")

        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            print(f"{Fore.RED}[!] Warning! Security engines flagged this link:")
            for engine, d in results.items():
                if d["category"] in ("malicious", "suspicious"):
                    print(f"  - {engine}: {d['result']} ({d['category']})")
        else:
            print(f"{Fore.GREEN}[+] VirusTotal: the link looks safe.")
    except Exception as e:
        print(f"{Fore.RED}[!] VirusTotal check failed: {e}")


def check_url(url):
    print(f"\n{Fore.BLUE}[*] Checking: {url}")
    local_analysis(url)
    virustotal_check(url)


if __name__ == "__main__":
    print(f"{Fore.MAGENTA}=== URL Scanner (Hybrid Mode) ===")
    if not API_KEY:
        print(f"{Fore.RED}[!] Set your VirusTotal API key in the VT_API_KEY "
              f"environment variable (see README).")
    else:
        while True:
            target = input(f"\n{Fore.GREEN}Enter a URL (or 'q' to quit): {Fore.RESET}").strip()
            if target.lower() == "q":
                print(f"{Fore.MAGENTA}Goodbye.")
                break
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            check_url(target)
