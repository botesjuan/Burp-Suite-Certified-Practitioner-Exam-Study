import sys
import logging
import argparse
import urllib3

import requests

import urils    # script written by @tjc_  https://youtu.be/YYsZpJ83azQ


log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="{asctime} [{threadName}][{levelname}][{name}] {message}",
    style="{",
    datefmt="%H:%M:%S",
)
urllib3.disable_warnings(urllib3.execeptions.InsecureRequestWarning)


def main(args):
    pass
    
    
if __name__ == "__main__":
    args = utils.parse_args(sys.argv)
    main(args)
    
    
