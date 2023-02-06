# source of the code https://youtu.be/HsHLc6U0IwQ?t=443
class Site:
    def __init__(self,url, no_proxy, session=None)
        self.base_url = utils.normalize_url(url)
        self.login_url = self.base_url + "login"
        self.no_proxy = no_proxy
        self.session = session
        
        
    def is_solved(self):
        def _is_solved(url, no_proxy):
            log.info("Checking if solved.")
            if self.no_proxy:
                resp = requests.get(self.base_url)
            else:
                resp = requests.get(self.base_url, proxies=PROXIES, verify=False)
            if "Congratulations, you solved the lab!" in resp.text:
                log.info("Lab is solved")
                return True
                
        solved = _is_solved(self)
        if solved:
            return True
        else:
            time.sleep(2)
            _is_solved(self)

