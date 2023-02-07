import re
import time
import logging
import urllib3

import requests

from utils import utils		# source of the code https://youtu.be/HsHLc6U0IwQ?t=443


log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Site:
    def __init__(self, url, no_proxy, session=None):
        self.base_url = utils.normalize_url(url)
        self.no_proxy = no_proxy
        self.session = session
	
    def get_hint(self):
    	log.info("Get Hint")
    	if self.no_proxy:
    		resp = requests.get(self.base_url)
    	else:
    		resp = requests.get(self.base_url, proxies=utils.PROXIES, verify=False)
    	pattern = re.compile(r'id="hint">.*?: \'(.*?)\'')
    	m = pattern.search(resp.text)
    	log.info(f"Found hint: {m[1]}")
    	return m[1]
    	
    def is_solved(self):
        def _is_solved(self):
            log.info("Checking if Lab is solved?")
            if self.no_proxy:
                resp = requests.get(self.base_url)
            else:
                resp = requests.get(self.base_url, proxies=utils.PROXIES, verify=False)
            if "Congratulations, you solved the lab!" in resp.text:
                log.info("Lab Completed.")
                return True
                
        solved = _is_solved(self)
        if solved:
            return True
        else:
            time.sleep(2)
            _is_solved(self)
