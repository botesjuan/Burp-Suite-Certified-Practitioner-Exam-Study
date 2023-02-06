import sys
import time
import logging
import argparse
import urllib3

import requests


PROXIES = {
    "http": "127.0.0.1:8080",
    "https":"127.0.0.1:8080"
}
log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="{asctime} [{threadName}][{levelname}][{name}] {message}",
    style="{",
    datefmt="%H:%M:%S",
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args(args: list):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n", "--no-proxy", default=False, action="store_true", help="do not use proxy"
    )
    parser.add_argument("url", help="url of target")
    return parser.parse_args()
    
    
def normalize_url(url):
    if not url.endswith("/"):
        url = url + "/"
    return url
    
    
def is_solved(url, no_proxy):
    def _is_solved(url, no_proxy):
        log.info("Checking if solved.")
        if no_proxy:
            resp = requests.get(url)
        else:
            resp = requests.get(url, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            log.info("lab solved")
            return True
            
    solved = _is_solved(url, no_proxy)
    if solved:
        return True
    else:
        time.sleep(2)
        _is_solved(url, no_proxy)


