import re
import sys
import logging

import requests

from utils import utils   # this script was created from YouTube https://youtu.be/YYsZpJ83azQ tutorial by @tjc_   
from utils.site import Site


log = logging.getLogger(__name__)


class Shop(Site):
    def __init__(self, url, no_proxy, session=None):   #  part of arguments given is 'self' automatically included
    	super().__init__(url, no_proxy, session)
        self.login_url = self.base_url + "login"
        self.category_url = self.base_url + "filter?category="

    def login(self, username, password):
        log.info("Login Attempt to shop")
        if self.no_proxy:
            resp = self.session.get(self.login_url)
        else:
            resp = self.session.get(self.login_url, proxies=utils.PROXIES, verify=False)
        if not resp.status_code == 200:
            log.error("Could not get login page. Exit Program!")
            sys.exit()
        else:
            # print(resp.text) # debugging 
            pattern = re.compile(r'name="csrf" value="(.*?)"')
            m = pattern.search(resp.text)
            csrf_token = m[1]
            log.info("Found CSRF token: {csrf_token}")
            data = {
                "csrf": csrf_token,
                "username": username,
                "password": password,
            }
            log.info("Attempt login bypass")
            if self.no_proxy:    #    provide option to set proxy or run script with no proxy
                resp = self.session.post(self.login_url, data=data)
            else:
                resp = self.session.post(
                    self.login_url, data=data, proxies=utils.PROXIES, verify=False
                )
            if resp.status_code == 200:
                log.info("Successfully bypassed login!")
