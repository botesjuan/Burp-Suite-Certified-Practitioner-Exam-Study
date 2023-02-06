import re
import sys
import logging

import requests

import utils   # this script was created from https://youtu.be/YYsZpJ83azQ tutorial by @tjc_   


log = logging.getLogger(__name__)


class Shop():
    def __init__(self, url, no_proxy, session):   #  part of arguments given is 'self' automatically included
        self.base_url = utils.normalize_url(url)
        self.login_url = self.base_url + "login"
        self.no_proxy = no_proxy
        self.session = session

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
