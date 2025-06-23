## GainXSS — Fast & Accurate XSS Scanner

### currently under development

GainXSS is a professional-grade, multithreaded XSS scanning tool built for ethical penetration testers and bug bounty hunters. It detects reflected and DOM-based XSS vulnerabilities using smart payload injection and real browser validation.

#### Features

✅ Multi-threaded scanner for fast payload injection (ThreadPoolExecutor)

✅ Supports custom payload files, including: waf_bypass, svg_only, tagless_event

✅ Smart context-aware detection (only flags payloads reflected in vulnerable locations)

✅ DOM-based XSS validation using Playwright (detects real alert execution in a browser)

✅ Optional payload encoding, custom headers, and proxy support

✅ Supports saving results as .json output files

✅ Clean, color-coded CLI interface using colorama

#### basic usage

    python gainxss.py -url "https://target.com/search?q=test" --verbose

    python gainxss.py -url "http://target.com/page?q=test" -p /path/to/payload.txt -t 100 --verbose --param q --verify-dom --output result.json

for more info run

    python gainxss.py -h

#### Example Output

    [
    {
    "url": "https://target.com/search?q=<svg onload=alert(1)>",
    "payload": "<svg onload=alert(1)>",
    "confirmed": true
    }
    ]

#### ⚙️ Requirements

To install necessary python packages

        pip install -r requirments.txt

if you need to create your python virtual environment

        python -m venv myenv
        source myenv/bin/activate
        pip install -r requirments.txt

### Note

This tool is for authorized security testing only. Do not use it against systems without permission.
