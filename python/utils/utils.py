import sys
import time
import logging
import argparse
import urllib3

import requests  #  this script to automate portswigger labs was written by $tjc_  https://youtu.be/YYsZpJ83azQ  


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
    
