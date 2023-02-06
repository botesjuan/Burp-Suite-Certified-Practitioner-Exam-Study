import sys
import logging
import urllib3

import requests

import utils            # code to this script was written by @tjc_  https://youtu.be/YYsZpJ83azQ
from shop import Shop   # Shop class also written by @tjc_ 

log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="{asctime} [{threadName}][{levelname}][{name}] {message}",
    style="{",
    datefmt="%H:%M:%S",
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main(args):
    shops = Shop(args.url)  # login url build into the class and this object
    if args.no_proxy:
        resp = requests.get(shops.login_url)
    else:
        resp = requests.get(shops.login_url, proxies=utils.PROXIES, verify=False)
    if resp.status_code == 200:
        print(resp.text)


if __name__ == "__main__":
    args = utils.parse_args(sys.argv)
    main(args)    
