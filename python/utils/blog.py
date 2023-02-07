import re
import sys
import logging
import urllib3

import requests

from utils import utils   ## the original code written by @tjc_  https://youtu.be/HsHLc6U0IwQ?t=443  
from utils.site import Site


log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Blog(Site):
	def __init__(self, url, no_proxy, session=None):     #  part of arguments given is 'self' automatically included
		super().__init__(url, no_proxy, session)
					
	def search(self, search_term):
		url = self.base_url + '?search=' + search_term
		log.info(f"Searching url: {url}")
		if self.no_proxy:
			resp = requestis.get(url)
		else:
			resp = requests.get(url, proxies=utils.PROXIES, verify=False)
		return resp
