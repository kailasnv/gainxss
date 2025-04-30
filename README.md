## 🔍 GainXSS — Fast & Accurate XSS Scanner

### currently under development

GainXSS is a professional-grade, multithreaded XSS scanning tool built for ethical penetration testers and bug bounty hunters. It detects reflected and DOM-based XSS vulnerabilities using smart payload injection and real browser validation.

#### 🚀 Features

✅ Multi-threaded scanner for fast payload injection (ThreadPoolExecutor)

✅ Supports custom payload files, including: waf_bypass, svg_only, tagless_event

✅ Smart context-aware detection (only flags payloads reflected in vulnerable locations)

✅ DOM-based XSS validation using Playwright (detects real alert execution in a browser)

✅ Optional payload encoding, custom headers, and proxy support

✅ Supports saving results as .json output files

✅ Clean, color-coded CLI interface using colorama

#### 🎯 Use Cases

- Ethical hacking & web app pentesting
- Red team toolkits and recon automation
- Bypassing WAF filters and JS sanitizers
- Testing SVG/image/profile upload vectors
- DOM-based validation for real exploitability

#### Payload Support

You can use one of the included payload sets or your own:

- payloads_optimized.txt → Clean, effective XSS payloads
- payloads_waf_bypass.txt → Obfuscated payloads to bypass filters
- payloads_svg_only.txt → XSS via <svg> contexts
- payloads_tagless_event.txt → Payloads using only attributes/events

#### basic usage

python gainxss.py -url "https://target.com/search?q=" -p payloads/payloads_optimized.txt --param q --verify-dom

For help, run → python gainxss.py -h

📁 Example Output
[
{
"url": "https://target.com/search?q=<svg onload=alert(1)>",
"payload": "<svg onload=alert(1)>",
"confirmed": true
}
]

### ⚙️ Requirements

- Python
- Playwright (for DOM validation):

  pip install playwright
  playwright install

### 📌 Note

This tool is for authorized security testing only. Do not use it against systems without permission.
