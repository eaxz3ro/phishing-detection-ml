## **Overview**

This is a machine learning-based email security solution designed to combine URL feature extraction, machine learning classification, and human-in-the-loop feedback to detect and stop phishing attacks in real-time. The system uses a Flask-based dashboard for live threat tracking and incident handling.

## **Features**

### **Core Functionalities**

| Feature | Description |
|---------|-------------|
| **Real-Time Email Monitoring** | Monitors inbox and junk folders via IMAP protocol |
| **URL Feature Extraction** | Analyzes URL length, digit count, suspicious keywords, TLDs, and IP addresses |
| **Machine Learning Classification** | Uses Logistic Regression for phishing URL detection |
| **Human-in-the-Loop Feedback** | Administrators review and correct misclassifications |
| **Flask Dashboard** | Web-based interface for live threat tracking |
| **Threat Intelligence Integration** | VirusTotal, OpenPhish, and WHOIS lookups |
| **Model Retraining** | Continuous improvement with new labeled data |

### **URL Features Analyzed**

| Feature | Description |
|---------|-------------|
| **URL Length** | Excessively long URLs indicate obfuscation |
| **Digit Count** | High digit frequency suggests IP address mimicry |
| **Number of Dots** | Unusually high count signals subdomain abuse |
| **IP Address Presence** | Raw IPs often indicate phishing/malware servers |
| **Suspicious Keywords** | "login," "secure," "account," "paypal," etc. |
| **Top-Level Domains** | Uncommon TLDs like .xyz, .ru, .tk |
| **Random String Detection** | Long strings with low vowel-to-consonant ratios |

### **User Experience Features**

- **Live Dashboard** - Real-time email monitoring with threat alerts
- **Admin Controls** - Manual review, labeling, and model retraining
- **Threat Intelligence** - VirusTotal, OpenPhish, and WHOIS integration
- **Privacy-Focused** - Only extracts URLs and metadata, no full email storage
- **Cross-Platform** - Works on Linux, Windows, and macOS

---

## **Technologies Used**

### **Programming Language**

Python 3.x     

### **Frameworks**

| Framework | Purpose |
|-----------|---------|
| **Flask** | Web framework for dashboard |
| **Scikit-learn** | Machine learning library |
| **Jinja2** | Server-side templating |

### **Libraries & Modules**

| Library | Purpose |
|---------|---------|
| **imaplib** | IMAP email fetching |
| **BeautifulSoup** | HTML parsing and URL extraction |
| **Logistic Regression** | Phishing classification model |
| **Joblib** | Model serialization |
| **re** | Regular expression for URL detection |

### **Infrastructure**

| Component | Purpose |
|-----------|---------|
| **Mailcow** | Mail server with domain, user, and filter configuration |
| **VirusTotal API** | Malware detection via file hashes |
| **OpenPhish** | Known phishing URL feed |
| **WHOIS** | Domain registration lookup |

---

## **Workflow**

```
Email Received → IMAP Fetch → URL Extraction → Feature Analysis 
    ↓
Model Prediction (Phishing/Legitimate)
    ↓
Dashboard Display → Admin Review → Feedback → Model Retraining
```

---

## **Installation**

### **Prerequisites**

- Python 3.6 or higher
- pip package manager
- Mailcow mail server (for full deployment)

### **Step 1: Clone the Repository**

```bash
git clone https://github.com/eaxz3ro/phishing-detection-ml
```

### **Step 2: Navigate to Project Directory**

```bash
cd phishing-detection-ml
```

### **Step 3: Create Virtual Environment (Recommended)**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### **Step 4: Install Dependencies**

```bash
pip3 install -r requirements.txt
```

### **Dependencies**

```txt
flask
scikit-learn
beautifulsoup4
requests
joblib
python-dotenv
```

---

## **Usage**

### **Launch Application**

```bash
# Start Flask dashboard
python3 app.py
```

### **1. Configure Mail Server**

Set up Mailcow with:

- Domain creation
- User creation
- Filter implementation

### **2. Monitor Emails**

The system automatically:

1. Polls IMAP server for new emails
2. Extracts URLs from email body
3. Analyzes URL features
4. Classifies phishing risk
5. Displays results on dashboard

### **3. Use Dashboard**

Access the dashboard at:

```
http://localhost:5000
```

Dashboard displays:

- Total emails processed
- URLs extracted
- Classification results
- Email metadata (sender, subject, timestamp)
- URL analysis breakdown

### **4. Admin Actions**

On the `/actions` endpoint:

- **VirusTotal Scan** - Check file hashes for malware
- **OpenPhish Scan** - Compare URLs against known phishing feed
- **WHOIS Lookup** - Retrieve domain registration details
- **Label Correction** - Fix misclassifications
- **Model Retraining** - Update model with new labeled data

### **5. Save Results**

Classification results are saved to CSV for future analysis and model retraining.
