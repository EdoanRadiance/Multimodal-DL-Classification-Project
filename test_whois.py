import whois
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import math

def get_domain_info(url):
    """Retrieve WHOIS domain information."""
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        # Ensure creation_date and expiration_date are not lists
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        today = datetime.today()
        
        # Calculate age and registration length
        age = (today - creation_date).days if creation_date else -1
        registration_length = (expiration_date - creation_date).days if creation_date and expiration_date else -1
        
        return {'age': age, 'registration_length': registration_length}
    except Exception as e:
        print(f"WHOIS lookup failed for {url}: {e}")
        return {'age': -1, 'registration_length': -1}

def extract_url_features(url):
    """Extract features from the URL, including WHOIS information."""
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    
    # WHOIS-based features
    domain_info = get_domain_info(url)
    features['domain_age'] = domain_info.get('age', -1)
    features['domain_registration_length'] = domain_info.get('registration_length', -1)

    # Additional features
    # Ratio of digits in the URL
    digits = sum(c.isdigit() for c in url)
    features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0

    # Suspicious words: e.g., "login", "verify", "secure", etc.
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update']
    features['suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else -1

    # File extension: check if URL ends with a suspicious extension
    suspicious_extensions = ['.exe', '.zip', '.scr', '.bat']
    features['suspicious_extension'] = 1 if any(url.lower().endswith(ext) for ext in suspicious_extensions) else -1

    # Domain TLD: flag if TLD is unusual (customize as needed)
    tld = domain.split('.')[-1]
    common_tlds = ['com', 'org', 'net', 'edu']
    features['unusual_tld'] = 1 if tld not in common_tlds else -1

    return features

# Testing the WHOIS and URL feature extraction
url = "https://www.angelfire.com/goth/devilmaycrytonite/"  # Example URL to test
features = extract_url_features(url)

# Print the extracted features, including WHOIS information
print(features)
