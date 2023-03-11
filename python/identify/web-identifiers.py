import sys
import requests
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

now = datetime.datetime.now()

# Format the date and time as a string
date_string = now.strftime('%Y-%m-%d-%H-%M-%S')
print(f'\nThe time is now: {date_string}\n')

# Define ANSI escape codes for color
YELLOW = '\033[33m'
RED = '\033[31m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

# Check the number of command line arguments
if len(sys.argv) < 5 or len(sys.argv) > 6:
    print(f'\n{YELLOW}Usage: python web_checker.py <url> <SEARCH_headers_TERMS_file> <SEARCH_body_TERMS_file>{RESET} {BLUE}[--screenshot]{RESET}\n')
    sys.exit(1)

url = sys.argv[1]
print(f'\n{YELLOW}Supplied {BOLD}TARGET{RESET} from the command line argument:{RESET} {url}')
SEARCH_headers_TERMS_file = sys.argv[2]
print(f'{YELLOW}Supplied {BOLD}HEADERS{RESET} input file containing search terms:{RESET} {url}')
SEARCH_body_TERMS_file = sys.argv[3]
print(f'{YELLOW}Supplied {BOLD}BODY{RESET} input file containing search terms:{RESET} {url}\n')

# Read the search terms from the files
with open(SEARCH_headers_TERMS_file, 'r') as f:
    SEARCH_headers_TERMS = [line.strip() for line in f]
with open(SEARCH_body_TERMS_file, 'r') as f:
    SEARCH_body_TERMS = [line.strip() for line in f]

# Check if the --screenshot option is specified
if len(sys.argv) == 5 and sys.argv[4] == '--screenshot':
    # Set up the Selenium WebDriver with headless Chrome
    options = Options()
    options.add_argument('--headless')
    #driver = webdriver.Chrome(options=options)
    driver = webdriver.Chrome(ChromeDriverManager().install())

    # Navigate to the URL and take a screenshot
    driver.get(url)
    driver.save_screenshot('screenshot-' + date_string + '.png')
    driver.quit()

response = requests.get(url)
print(f'{BLUE}[+] Making the request to the URL\n{RESET}')

print(f'\n# Check the response {BOLD}HEADERS{RESET} for the search terms:')
for header, value in response.headers.items():
    for term in SEARCH_headers_TERMS:
        if term.lower() in header.lower():            
            print(f'Found in header: {YELLOW}{term}{RESET} - {GREEN}{header}: {value}{RESET}')

print(f'\n# Check the response {BOLD}BODY{RESET} for the search terms:')
for line in response.text.split('\n'):
    for term in SEARCH_body_TERMS:
        if term.lower() in line.lower():
            print(f'Found in body: {YELLOW}{term}{RESET} - {RED}{line}{RESET}')
