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
        
    def get_response(self, url):
        log.info("Get response")
        if self.no_proxy:
            resp = requests.get(url)
        else:
            resp = requests.get(url, proxies=utils.PROXIES, verify=False)
        return resp
		
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
                log.info("Lab is Completed.")
                return True
                
        solved = _is_solved(self)
        if solved:
            return True
        else:
            time.sleep(2)
            _is_solved(self)

    def get_exploit_url(self):
        log.info("Get Exploit Server URL")
        resp = self.get_response(self.base_url)
        pattern = re.compile(r"id='exploit-link'.*href='(.*?)'>")
        m = pattern.search(resp.text)
        log.info(f"Exploit Server URL: {m[1]}")
        return m[1]

    def post_exploit(self,
        url_is_https="on", 
        response_file="/exploit", 
        response_head="HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
        response_body="Hello World!",
        formAction="DELIVER_TO_VICTIM"
    ):
        log.info("Posting Exploit Server Payload.")
        exploit_url = self.get_exploit_url()
        data = {
            "urlIsHttps":url_is_https,
            "responseFile":response_file,
            "responseHead":response_head,
            "responseBody":response_body,
            "formAction":formAction
        }
        if self.no_proxy:
            requests.post(exploit_url, data=data)
        else:
            requests.post(exploit_url, data=data, proxies=utils.PROXIES, verify=False)
        log.info("Posting Exploit Server Payload.")
