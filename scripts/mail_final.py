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
import pandas as pd
from sklearn.metrics import accuracy_score

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

IMAP_SERVER = "127.0.0.1"
EMAIL_ACCOUNT = "MONITORING-MAIL-HERE"
EMAIL_PASSWORD = "PASSWORD-HERE"
MAILBOX = "INBOX"

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

    full_urls = set(clean_url(u) for u in re.findall(r'https?://[^\s\'"<>]+', clean_text))
    partial_urls_raw = set(clean_url(u) for u in re.findall(r'\b(?:www\.|[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?', clean_text))

    partial_urls = set()
    for url in partial_urls_raw:
        if not any(url in full_url for full_url in full_urls):
            partial_urls.add(url)

    all_urls = sorted(full_urls.union(partial_urls))
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
        raw_email = msg_data[0][1]
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

def print_email(msg):
    subject = decode_mime_words(msg.get("Subject"))
    from_ = decode_mime_words(msg.get("From"))
    to_ = decode_mime_words(msg.get("To"))
    date_ = msg.get("Date")

    print("=" * 60)
    print(f"From   : {from_}")
    print(f"To     : {to_}")
    print(f"Date   : {date_}")
    print(f"Subject: {subject}")

    body = get_email_body(msg)
    urls, clean_body = extract_all_links(body)

    print("\n--- Body (cleaned) ---")
    print(clean_body.strip())

    print("\n--- URLs Found ---")
    if urls:
        predictions = phishing_pipeline.predict(urls)
        extractor = URLFeatureExtractor()
        for i, url in enumerate(urls):
            if extractor.is_www_no_random_no_path(url) == 0:
                predictions[i] = 0

        for url, label in zip(urls, predictions):
            print(f" - {url}  -->  {'Phishing' if label == 1 else 'Safe'}")
    else:
        print(" No URLs found.")

    print("\n--- Attachments ---")
    has_attachment = False
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            has_attachment = True
            filename = decode_mime_words(part.get_filename())
            if filename:
                payload = part.get_payload(decode=True)
                filehash = calculate_hash(payload)
                print(f" - {filename} | MD5: {filehash}")
    if not has_attachment:
        print(" No attachments.")

def main_loop():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
    mail.select(MAILBOX)

    emails = fetch_emails_since(mail, datetime(1970, 1, 1, tzinfo=timezone.utc))
    if not emails:
        print("No emails found at startup.")
        last_email_datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)
    else:
        emails.sort(key=lambda x: x[0])
        last_email_datetime = emails[-1][0]
        print(f"Startup: found {len(emails)} emails, printing all:")
        for dt, msg in emails:
            print_email(msg)

    try:
        while True:
            emails = fetch_emails_since(mail, last_email_datetime)
            new_emails = []
            for email_dt, msg in emails:
                if email_dt > last_email_datetime:
                    new_emails.append((email_dt, msg))
            if new_emails:
                new_emails.sort(key=lambda x: x[0])
                for email_dt, msg in new_emails:
                    print("\nNew email received:")
                    print_email(msg)
                    last_email_datetime = max(last_email_datetime, email_dt)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        mail.logout()

if __name__ == "__main__":
    main_loop()
