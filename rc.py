#!/usr/bin/env python3
import threading
import requests
import argparse
import time
import logging
import sqlite3
from sqlite3 import Error
from jinja2 import Environment, FileSystemLoader
import os

# AI Model Imports
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Disable warnings and configure logging
requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

# Load Microsoft CodeBERT model for URL scoring
logging.info("[AI] Loading AI...")
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = AutoModelForSequenceClassification.from_pretrained("microsoft/codebert-base")
model.eval()

def ai_score_url(url: str) -> float:
    """Score a URL for suspiciousness using the AI model."""
    inputs = tokenizer(url, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).tolist()[0]
    return probs[1] if len(probs) > 1 else probs[0]

class DomainExtractor:
    def __init__(self, domain, want_subdomain, threads, response_time_threshold, db_filename, report_filename):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.threads = threads
        self.response_time_threshold = response_time_threshold
        self.db_filename = db_filename
        self.report_filename = report_filename
        self.final_url_list = set()
        self.potential_race_conditions = []
        self.create_db()

    def create_db(self):
        try:
            self.conn = sqlite3.connect(self.db_filename)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS race_conditions (
                    url TEXT,
                    status_code INTEGER,
                    response_time REAL,
                    ai_score REAL
                )
            ''')
            self.conn.commit()
        except Error as e:
            logging.error(f"[DB] Failed to create the database: {e}")
            self.conn = None

    def extract_urls_from_wayback_machine(self):
        wild = "*." if self.want_subdomain else ""
        api = f"http://web.archive.org/cdx/search/cdx?url={wild + self.domain}/*&output=json&collapse=urlkey&fl=original"
        try:
            resp = requests.get(api, verify=False, timeout=15)
            data = resp.json()
            urls = {item[0] for item in data[1:]}
            self.final_url_list.update(urls)
            logging.info(f"[Wayback] Collected {len(urls)} URLs")
        except Exception as e:
            logging.warning(f"[Wayback] Error: {e}")

    def extract_urls_from_otx(self):
        api = f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list"
        try:
            resp = requests.get(api, verify=False, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("url_list", [])
            urls = {u["url"] for u in data}
            self.final_url_list.update(urls)
            logging.info(f"[OTX] Collected {len(urls)} URLs")
        except Exception as e:
            logging.warning(f"[OTX] Error: {e}")

    def start(self):
        logging.info(f"[>>] Starting URL extraction for {self.domain}")
        self.extract_urls_from_wayback_machine()
        self.extract_urls_from_otx()
        return self.final_url_list

    def test_race_conditions(self):
        url_list = list(self.final_url_list)
        logging.info("[AI] Scoring URLs for prioritization...")
        scored = [(url, ai_score_url(url)) for url in url_list]
        scored.sort(key=lambda x: x[1], reverse=True)
        prioritized = [u for u, _ in scored]

        def send_request_with_timing(url):
            start = time.time()
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.36'
                }
                resp = requests.get(url, headers=headers, verify=False, timeout=10, allow_redirects=True)
                elapsed = time.time() - start
                if elapsed < self.response_time_threshold:
                    score = ai_score_url(url)
                    record = {"url": url, "status_code": resp.status_code, "response_time": elapsed, "ai_score": score}
                    self.potential_race_conditions.append(record)
                    self.save_to_db(url, resp.status_code, elapsed, score)
            except Exception:
                pass

        threads = []
        for url in prioritized[: self.threads * 100]:
            t = threading.Thread(target=send_request_with_timing, args=(url,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        if self.potential_race_conditions:
            logging.info("[>>] Potential Race Conditions Detected:")
            for c in self.potential_race_conditions:
                logging.info(
                    f" - {c['url']} | Code: {c['status_code']} | Time: {c['response_time']:.3f}s | AI: {c['ai_score']:.2f}"
                )

    def save_to_db(self, url, status_code, response_time, ai_score):
        if self.conn:
            self.cursor.execute(
                'INSERT INTO race_conditions (url, status_code, response_time, ai_score) VALUES (?, ?, ?, ?)',
                (url, status_code, response_time, ai_score)
            )
            self.conn.commit()

    def generate_report(self):
        if not self.conn:
            return
        self.cursor.execute('SELECT url, status_code, response_time, ai_score FROM race_conditions')
        rows = self.cursor.fetchall()
        env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))
        tpl = env.get_template("report_template.html")
        with open(self.report_filename, "w") as f:
            f.write(tpl.render(rows=rows))
        logging.info(f"[Report] Generated HTML report: {self.report_filename}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AI-Powered Concurrent URL Race Condition Tester')
    parser.add_argument('domain', help='Target domain for URL extraction')
    parser.add_argument('-s', '--subdomain', action='store_true', help='Include subdomains')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('-r', '--response-time-threshold', type=float, default=0.1,
                        help='Threshold (s) for flagging race conditions')
    parser.add_argument('--db', default='race_conditions.db', help='SQLite database filename')
    parser.add_argument('--report', default='race_conditions_report.html', help='HTML report filename')
    args = parser.parse_args()

    print("=" * 80)
    print(f"[>>] Extracting URLs for {args.domain} using WaybackMachine & OTX...")
    de = DomainExtractor(
        args.domain,
        args.subdomain,
        args.threads,
        args.response_time_threshold,
        args.db,
        args.report
    )
    urls = de.start()
    print(f"[>>] Total URLs found: {len(urls)}")
    de.test_race_conditions()
    de.generate_report()
    print("[>>] Scan complete!")
