import pandas as pd
import re
import joblib
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from urllib.parse import urlparse
from types import SimpleNamespace

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

def main():
    df = pd.read_csv("flags.csv")
    X = df["url"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("features", FeatureUnion([
            ("tfidf", TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 6), max_features=5000)),
            ("custom_features", URLFeatureExtractor()),
        ])),
        ("classifier", LogisticRegression(solver="liblinear", class_weight='balanced', random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("=== Test Set Evaluation (from training split) ===")
    print(classification_report(y_test, y_pred))

    train_acc = pipeline.score(X_train, y_train)
    print(f"Training Accuracy: {train_acc:.4f}")

    joblib.dump(pipeline, "phishing.pkl")
    print("Model saved as phishing.pkl")

if __name__ == "__main__":
    main()
