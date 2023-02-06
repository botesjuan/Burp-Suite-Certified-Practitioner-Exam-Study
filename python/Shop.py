import utils


class Shop():
    def __init__(url):
        base_url = utils.normalize_url(url)
        login_url = base_url + "login"
        