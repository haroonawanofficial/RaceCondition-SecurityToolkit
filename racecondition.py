import threading
import requests
import argparse
import time
import logging
import sqlite3
from sqlite3 import Error
from jinja2 import Environment, FileSystemLoader
import os

requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

class DomainExtractor:
    def __init__(self, domain, want_subdomain, thread_number, response_time_threshold, db_filename, report_filename):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.thread_number = thread_number
        self.final_url_list = set()
        self.potential_race_conditions = []
        self.response_time_threshold = response_time_threshold
        self.db_filename = db_filename
        self.report_filename = report_filename

        self.create_db()

    def create_db(self):
        try:
            self.conn = sqlite3.connect(self.db_filename)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS race_conditions (
                    url TEXT,
                    status_code INT,
                    response_time REAL
                )
            ''')
        except Error as e:
            pass
            #logging.error(f"Failed to create the database: {str(e)}")
            self.conn = None

    def start(self):
        self.extract_urls_from_wayback_machine()
        self.extract_urls_from_otx()
        return self.final_url_list

    def extract_urls_from_wayback_machine(self):
        wild_card = "*." if self.want_subdomain else ""
        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card + self.domain}/*&output=json&collapse=urlkey&fl=original"

        response = requests.get(url, verify=False)
        if response.status_code == 200:
            data = response.json()
            try:
                urls_list = data[1:]  # Skip the first line
                final_urls_list = {item[0] for item in urls_list}
                self.final_url_list.update(final_urls_list)
            except Exception as e:
                pass
                #logging.error(f"Failed to extract URLs from WaybackMachine: {str(e)}")
        else:
            pass
            #logging.error(f"Failed to fetch data from WaybackMachine. Status code: {response.status_code}")

    def extract_urls_from_otx(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list"
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            data = response.json()
            urls_list = data.get("url_list", [])
            final_urls_list = {url["url"] for url in urls_list}
            self.final_url_list.update(final_urls_list)
        else:
            pass
            #logging.error(f"Failed to fetch data from AlienVault OTX. Status code: {response.status_code}")

    def test_race_conditions(self):
        url_list = list(self.final_url_list)

        def send_request_with_timing(url):
            start_time = time.time()
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
                response = requests.get(url, headers=headers, verify=False, timeout=10, allow_redirects=True)
                end_time = time.time()
                response_time = end_time - start_time

                if response_time < self.response_time_threshold:
                    self.potential_race_conditions.append(
                        {
                            "url": url,
                            "status_code": response.status_code,
                            "response_time": response_time,
                        }
                    )
                    self.save_to_db(url, response.status_code, response_time)

            except requests.exceptions.RequestException as e:
                pass
                    #logging.error(f"URL: {url}, Error: {str(e)}")

        threads = []
        for url in url_list:
            thread = threading.Thread(target=send_request_with_timing, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if self.potential_race_conditions:
            logging.info("\n[>>] [Potential Race Conditions]:")
            for condition in self.potential_race_conditions:
                logging.info(
                    f"URL: {condition['url']}, Status Code: {condition['status_code']}, "
                    f"Response Time: {condition['response_time']} seconds"
                )

    def save_to_db(self, url, status_code, response_time):
        if self.conn:
            self.cursor.execute('INSERT INTO race_conditions (url, status_code, response_time) VALUES (?, ?, ?)',
                                (url, status_code, response_time))
            self.conn.commit()

    def generate_report(self):
        if not self.conn:
            return

        self.cursor.execute('SELECT * FROM race_conditions')
        rows = self.cursor.fetchall()

        env = Environment(loader=FileSystemLoader(os.path.abspath(os.path.dirname(__file__))))
        template = env.get_template("report_template.html")

        with open(self.report_filename, "w") as report_file:
            report_file.write(template.render(rows=rows))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Concurrent URL Request Testing')
    parser.add_argument('domain', help='Domain to extract URLs from')
    parser.add_argument('-s', '--subdomain', action='store_true', help='Include subdomains')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('-r', '--response-time-threshold', type=float, default=0.1, help='Response time threshold for potential race conditions')
    parser.add_argument('--db', default='race_conditions.db', help='Database filename')
    parser.add_argument('--report', default='race_conditions_report.html', help='HTML report filename')
    args = parser.parse_args()

    print("=========================================================================")
    print(f"[>>] Extracting Domain URLs from: WaybackMachine, AlienVault OTX for {args.domain}...")

    domain_extractor = DomainExtractor(args.domain, args.subdomain, args.threads, args.response_time_threshold,
                                       args.db, args.report)
    final_url_list = domain_extractor.start()

    print("=========================================================================")
    print("[>>] [Total URLs to Test]: ", len(final_url_list))

    domain_extractor.test_race_conditions()
    domain_extractor.generate_report()
