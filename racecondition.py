import threading
import requests
import argparse
import sys
import numpy as np
import signal
import time

requests.packages.urllib3.disable_warnings()

GREEN, RED, WHITE, YELLOW, MAGENTA, BLUE, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Define a set to store processed URLs
processed_urls = set()

class DomainExtractor:
    def __init__(self, domain, want_subdomain, threadNumber):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.threadNumber = threadNumber
        self.final_url_list = set()

    def start(self):
        self.extractUrlsFromWaybackMachine()
        self.extractUrlsFromOTX()

        return self.final_url_list
    
    def extractUrlsFromWaybackMachine(self):
        if self.want_subdomain:
            wild_card = "*."
        else:
            wild_card = ""

        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+self.domain}/*&output=json&collapse=urlkey&fl=original"
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            data = response.json()
            try:
                urls_list = data[1:]  # Skip the first line
                final_urls_list = {item[0] for item in urls_list}
                self.final_url_list.update(final_urls_list)
            except Exception as e:
                print(f"Failed to extract URLs from WaybackMachine: {str(e)}")
        else:
            print(f"Failed to fetch data from WaybackMachine. Status code: {response.status_code}")

    def extractUrlsFromOTX(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list"
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            data = response.json()
            urls_list = data.get("url_list", [])
            final_urls_list = {url["url"] for url in urls_list}
            self.final_url_list.update(final_urls_list)
        else:
            print(f"Failed to fetch data from AlienVault OTX. Status code: {response.status_code}")

    def test_race_conditions(self):
        url_list = list(self.final_url_list)  # Convert the set to a list

        def send_request_with_timing(url):
            start_time = time.time()  # Record the start time
            try:
                response = requests.get(url, verify=False, timeout=10)
                end_time = time.time()  # Record the end time
                response_time = end_time - start_time  # Calculate the response time

                if response_time < 0.1:
                    print(f"URL: {url}, Status Code: {response.status_code}, Response Time: {response_time} seconds (Potential Race Condition)")
                else:
                    print(f"URL: {url}, Status Code: {response.status_code}, Response Time: {response_time} seconds")

                # You can add more complex checks here, such as comparing response times or status codes
            except requests.exceptions.RequestException as e:
                print(f"URL: {url}, Error: {str(e)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Concurrent URL Request Testing')
    parser.add_argument('domain', help='Domain to extract URLs from')
    parser.add_argument('-s', '--subdomain', action='store_true', help='Include subdomains')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads')
    args = parser.parse_args()

    print("=========================================================================")
    print(f"[>>] Extracting Domain URLs from: WaybackMachine, AlienVault OTX for {args.domain}...")

    domain_extractor = DomainExtractor(args.domain, args.subdomain, args.threads)
    final_url_list = domain_extractor.start()

    print("=========================================================================")
    print("[>>] [Total URLs Tested] : ", len(final_url_list))

    # Concurrently test race conditions on the extracted URLs
    domain_extractor.test_race_conditions()
