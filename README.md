# URL Link Checker

A Python command-line tool that checks whether a link is safe or suspicious.
It combines a local page scan with the VirusTotal global database.

## Features
- **Local static analysis:** downloads the page and looks for phishing keywords and malware indicators
- **VirusTotal check:** shows how many security engines flag the link as harmless, suspicious or malicious
- Lists the engines that flagged the link
- Colored, easy-to-read terminal output

## Requirements
- Python 3.9+
- A free VirusTotal API key (https://www.virustotal.com)

## Installation
```bash
git clone https://github.com/meyrlankzh/check-url-links.git
cd check-url-links
pip install -r requirements.txt
```

## Set your API key
Linux / macOS:
```bash
export VT_API_KEY="your_api_key"
```
Windows (PowerShell):
```powershell
$env:VT_API_KEY="your_api_key"
```
Never put your key in the code or commit it to GitHub.

## Usage
```bash
python check_url.py
```
Enter a URL when asked, or `q` to quit.

## Example
```
Enter a URL (or 'q' to quit): example.com

[*] Checking: https://example.com
--- LOCAL ANALYSIS ---
[+] No suspicious content found in the page code.

=== VIRUSTOTAL RESULTS ===
Harmless:   60
Suspicious: 0
Malicious:  0
[+] VirusTotal: the link looks safe.
```

## How it works
1. The tool downloads the page and searches its HTML for suspicious keywords.
2. It submits the URL to the VirusTotal API and waits for the analysis.
3. It prints the combined result.

## Limitations
The local analysis is keyword-based, so it can produce false positives
(for example, a normal login page). Treat it as a hint, not a verdict.
The local scan also visits the page from your machine.

## License
MIT
