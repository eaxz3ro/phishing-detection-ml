import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
import re
import numpy as np
from urllib.parse import urlparse
from types import SimpleNamespace
from sklearn.base import BaseEstimator, TransformerMixin

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

def test_and_show_results(csv_path="dataset/train.csv", n=1000):
    pipeline = joblib.load("phishing_v2.pkl")
    extractor = URLFeatureExtractor()

    df = pd.read_csv(csv_path)

    if "url" not in df.columns or "label" not in df.columns:
        print("CSV must contain 'url' and 'label' columns.")
        return

    df_sample = df.sample(n=min(len(df), n), random_state=42).copy()
    urls = df_sample["url"].astype(str).fillna("")
    true_labels = df_sample["label"]
    predicted = pipeline.predict(urls)
    for i, url in enumerate(urls):
        if extractor.is_www_no_random_no_path(url) == 0:
            predicted[i] = 0

    print(f"\n{'URL':<60} {'Real':<6} {'Predicted':<9}")
    print("-" * 80)
    for url, real, pred in zip(urls, true_labels, predicted):
        print(f"{url:<60} {real:<6} {pred:<9}")

    acc = accuracy_score(true_labels, predicted)
    print(f"\nAccuracy on {len(df_sample)} samples from {csv_path}: {acc:.4f}")

if __name__ == "__main__":
    test_and_show_results()
