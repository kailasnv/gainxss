import argparse



#Argument Parser
def get_args():
    parser = argparse.ArgumentParser(description="GainXSS - Fast XSS Scanner 🛡️")
    parser.add_argument("-url", help="Target URL (e.g., http://example.com/search?q=)", required=True)
    parser.add_argument("-p", "--payloads", help="File with XSS payloads", default="payloads.txt")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("--param", help="Parameter name to inject payloads into", default="q")
    return parser.parse_args()


get_args()