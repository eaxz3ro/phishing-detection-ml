import imaplib
import email
from email.header import decode_header
import re
import hashlib
import time
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import unquote, urlparse
import warnings
from bs4 import MarkupResemblesLocatorWarning
import joblib
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from types import SimpleNamespace
from flask import Flask, jsonify, render_template, request
import threading
import subprocess
import os
import requests
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

IMAP_SERVER = "127.0.0.1"
EMAIL_ACCOUNT = "MAIL-ACCOUNT-HERE"
EMAIL_PASSWORD = "PASSWORD-HERE"
MAILBOX = "INBOX"
VT_API_KEY= "VIRUSTOTAL-API-KEY-HERE"
class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, random_string_length=8):
        self.random_string_length = random_string_length
        self.vowels = set('aeiou')

    def fit(self, X, y=None):
        return self

    def _ensure_scheme(self, url: str) -> str:
        url = (url or "").strip()
        url = url.strip("[]")
        if not re.match(r'^https?://', url, re.I):
            url = 'http://' + url
        return url

    def _safe_parse(self, url: str):
        try:
            return urlparse(self._ensure_scheme(url))
        except Exception:
            return SimpleNamespace(path='', query='', fragment='', hostname='')

    def has_random_string(self, url):
        parts = re.split(r'[./\-?=&]', (url or '').lower())
        for part in parts:
            if len(part) >= self.random_string_length:
                vowels_count = sum(ch in self.vowels for ch in part)
                if vowels_count <= 1:
                    return 1
        return 0

    def is_www_no_random_no_path(self, url):
        parsed = self._safe_parse(url)
        hostname = (parsed.hostname or '').strip('.')
        path_ok = (parsed.path == '' or parsed.path == '/')

        if hostname.startswith('www.') and path_ok and self.has_random_string(url) == 0:
            return 0
        else:
            return 1

    def transform(self, X):
        feats = []
        for url in X:
            u = (str(url) if url is not None else "")
            u_l = u.lower()
            feats.append([
                len(u),
                u.count('.'),
                sum(ch.isdigit() for ch in u),
                int(bool(re.search(r"https?://", u_l))),
                int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", u_l))),
                int(any(word in u_l for word in ['login', 'secure', 'account', 'verify', 'update', 'ebay', 'paypal'])),
                int(u_l.endswith('.xyz') or u_l.endswith('.ru')),
                self.has_random_string(u),
                self.is_www_no_random_no_path(u),
            ])
        return np.array(feats, dtype=float)

try:
    phishing_pipeline = joblib.load("phishing_v2.pkl")
    print("✅ Loaded phishing model.")
except Exception as e:
    print("❌ Failed to load phishing model:", e)
    exit(1)

def clean_url(url):
    return url.strip('<>"\'').rstrip(')')

def extract_all_links(text):
    text = unquote(text)
    soup = BeautifulSoup(text, "html.parser")
    clean_text = soup.get_text(separator=' ')
    clean_text = re.sub(r'\s+', ' ', clean_text)

    tld_pattern = r'\.(com|org|net|edu|gov|mil|int|info|biz|co|io|xyz|ru|me|online|tech|store|site|us|uk|ca|de|jp|fr|au|in|cn|br|za|nl|se|no|es|it|ch|tv|fm|me|gg|io|app|dev)\b'

    full_urls = set()
    for u in re.findall(r'https?://[^\s\'"<>]+', clean_text):
        u_clean = clean_url(u)
        if re.search(tld_pattern, u_clean, re.I):
            full_urls.add(u_clean)

    partial_urls_raw = set()
    candidate_urls = re.findall(r'\b(?:www\.|[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?', clean_text)
    for u in candidate_urls:
        u_clean = clean_url(u)
        if re.search(tld_pattern, u_clean, re.I):
            if not any(u_clean in full_url for full_url in full_urls):
                partial_urls_raw.add(u_clean)

    all_urls = sorted(full_urls.union(partial_urls_raw))
    return all_urls, clean_text

def get_email_body(msg):
    if msg.is_multipart():
        html_body = None
        plain_body = None
        for part in msg.walk():
            content_type = part.get_content_type()
            content_dispo = str(part.get("Content-Disposition"))
            if content_type == "text/html" and "attachment" not in content_dispo:
                html_body = part.get_payload(decode=True).decode(errors='ignore')
            elif content_type == "text/plain" and "attachment" not in content_dispo:
                plain_body = part.get_payload(decode=True).decode(errors='ignore')
        return html_body or plain_body or ""
    else:
        return msg.get_payload(decode=True).decode(errors='ignore')

def calculate_hash(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()

def parse_email_date(date_str):
    from email.utils import parsedate_to_datetime
    try:
        dt = parsedate_to_datetime(date_str)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def fetch_emails_since(mail, since_date):
    since_str = since_date.strftime("%d-%b-%Y")
    result, data = mail.search(None, f'(SINCE "{since_str}")')
    if result != "OK":
        print("Failed to search emails")
        return []
    email_ids = data[0].split()
    emails = []
    for eid in email_ids:
        result, msg_data = mail.fetch(eid, "(RFC822)")
        if result != "OK":
            continue

        raw_email = None
        for part in msg_data:
            if isinstance(part, tuple):
                raw_email = part[1]
                break

        if raw_email is None:
            continue

        msg = email.message_from_bytes(raw_email)
        date_str = msg.get("Date")
        email_dt = parse_email_date(date_str)
        if email_dt is None:
            continue
        emails.append((email_dt, msg))
    return emails

def decode_mime_words(value):
    if not value:
        return ""
    decoded_parts = decode_header(value)
    decoded_string = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            decoded_string += part.decode(encoding if encoding else "utf-8", errors="ignore")
        else:
            decoded_string += part
    return decoded_string

def email_to_dict(msg):
    subject = decode_mime_words(msg.get("Subject"))
    from_ = decode_mime_words(msg.get("From")).replace('">', '').replace('<', '').replace('>', '').strip()
    to_ = decode_mime_words(msg.get("To")).replace('">', '').replace('<', '').replace('>', '').strip()
    date_header = msg.get("Date")
    dt = parse_email_date(date_header)
    date_str = dt.isoformat() if dt else (date_header or "")
    body = get_email_body(msg)
    urls, clean_body = extract_all_links(body)

    extractor = URLFeatureExtractor()
    fixed_urls = [extractor._ensure_scheme(u) for u in urls]
    predictions = phishing_pipeline.predict(fixed_urls) if fixed_urls else []

    for i, url in enumerate(fixed_urls):
        if extractor.is_www_no_random_no_path(url) == 0:
            predictions[i] = 0

    url_info = [{"url": fixed_url, "label": int(pred)} for fixed_url, pred in zip(fixed_urls, predictions)]

    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = decode_mime_words(part.get_filename())
            if filename:
                payload = part.get_payload(decode=True)
                filehash = calculate_hash(payload)
                attachments.append({"filename": filename, "md5": filehash})

    return {
        "from": from_,
        "to": to_,
        "date": date_str,
        "subject": subject,
        "body": clean_body,
        "urls": url_info,
        "attachments": attachments,
    }

app = Flask(__name__)

emails_data = []
emails_lock = threading.Lock()

def make_email_key(email_dict):
    return (email_dict['date'], email_dict['from'], email_dict['subject'])

def background_email_fetcher():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
    
    folders_to_scan = ["INBOX", "Junk"]  

    emails_all = []

    for folder in folders_to_scan:
        mail.select(folder)
        emails = fetch_emails_since(mail, datetime(1970, 1, 1, tzinfo=timezone.utc))
        emails_all.extend(emails)

    if not emails_all:
        print("No emails found at startup.")
        last_email_datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)
    else:
        emails_all.sort(key=lambda x: x[0])  
        last_email_datetime = emails_all[-1][0]
        print(f"Startup: found {len(emails_all)} emails across folders.")

        with emails_lock:
            emails_data.clear()
            existing_keys = set()
            for _, msg in emails_all:
                e_dict = email_to_dict(msg)
                key = (e_dict['date'], e_dict['from'], e_dict['subject'])
                if key not in existing_keys:
                    emails_data.append(e_dict)
                    existing_keys.add(key)

    try:
        while True:
            new_emails_all = []
            for folder in folders_to_scan:
                mail.select(folder)
                new_emails = fetch_emails_since(mail, last_email_datetime)
                for email_dt, msg in new_emails:
                    if email_dt > last_email_datetime:
                        new_emails_all.append((email_dt, msg))

            if new_emails_all:
                new_emails_all.sort(key=lambda x: x[0]) 
                with emails_lock:
                    existing_keys = set((e['date'], e['from'], e['subject']) for e in emails_data)
                    for email_dt, msg in new_emails_all:
                        e_dict = email_to_dict(msg)
                        key = (e_dict['date'], e_dict['from'], e_dict['subject'])
                        if key not in existing_keys:
                            emails_data.append(e_dict)
                            existing_keys.add(key)
                        last_email_datetime = max(last_email_datetime, email_dt)

            time.sleep(5)
    except Exception as e:
        print("Background fetcher stopped:", e)
    finally:
        mail.logout()


@app.route('/virus_total_query', methods=['POST'])
def virus_total_query():
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({'error': 'Missing hash parameter'}), 400
    file_hash = data['hash']

    vt_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    vt_page_url = f'https://www.virustotal.com/gui/file/{file_hash}/detection'  
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = requests.get(vt_url, headers=headers, timeout=10)
        if response.status_code == 200:
            vt_data = response.json()
            return jsonify({'result': 'Result found', 'url': vt_page_url})
        elif response.status_code == 404:
            return jsonify({'result': 'Not found'}), 404
        else:
            return jsonify({'error': f'VirusTotal API error: {response.status_code}', 'details': response.text}), response.status_code
    except requests.RequestException as e:
        return jsonify({'error': str(e)}), 500



with open('feed.txt', 'r') as f:
    openphish_urls = set(line.strip() for line in f if line.strip())

@app.route('/check_openphish', methods=['POST'])
def check_openphish():
    data = request.get_json()
    url = data.get('url')
    domain = data.get('domain')

    if not url or not domain:
        return jsonify(error='Missing url or domain'), 400

    if url in openphish_urls:
        return jsonify(found=True)

    for feed_url in openphish_urls:
        if domain in feed_url:
            return jsonify(found=True)

    return jsonify(found=False)


def run_training():
    try:
        subprocess.run(['python3', 'retrain.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Training failed: {e}")

@app.route('/retrain', methods=['POST'])
def retrain():
    thread = threading.Thread(target=run_training)
    thread.start()
    return jsonify({"status": "Training started"}), 202
    
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/emails")
def get_emails():
    with emails_lock:
        return jsonify(emails_data)

@app.route("/actions")
def actions():
    with emails_lock:
        all_urls = []
        attachments = []
        for email in emails_data:
            all_urls.extend(email.get("urls", []))
            attachments.extend(email.get("attachments", []))

    seen_urls = set()
    unique_urls = []
    for item in all_urls:
        if item["url"] not in seen_urls:
            seen_urls.add(item["url"])
            unique_urls.append(item)

    seen_attachments = set()
    unique_attachments = []
    for att in attachments:
        key = (att.get("filename"), att.get("hash"))  
        if key not in seen_attachments:
            seen_attachments.add(key)
            unique_attachments.append(att)

    return render_template("actions.html",
                           email_data=emails_data,
                           unique_attachments=unique_attachments,
                           unique_urls=unique_urls)



@app.route('/save_flags', methods=['POST'])
def save_flags():
    csv_data = request.get_data(as_text=True)
    if not csv_data:
        return jsonify({"error": "No data received"}), 400

    try:
        with open('flags.csv', 'w', encoding='utf-8') as f:
            f.write(csv_data)
        return jsonify({"status": "Flags saved"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == "__main__":
    thread = threading.Thread(target=background_email_fetcher, daemon=True)
    thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
