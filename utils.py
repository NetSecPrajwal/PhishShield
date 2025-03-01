import re

# List of phishing-related keywords
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "update your password", "click here", "login now",
    "unauthorized activity", "suspicious login", "reset your password"
]

# List of suspicious domains
SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl.com", "ow.ly", "rb.gy"]

def check_suspicious_links(links):
    risky_links = [link for link in links if any(domain in link for domain in SUSPICIOUS_DOMAINS)]
    return risky_links

def check_suspicious_keywords(body_text):
    detected_keywords = [word for word in PHISHING_KEYWORDS if word in body_text.lower()]
    return detected_keywords
