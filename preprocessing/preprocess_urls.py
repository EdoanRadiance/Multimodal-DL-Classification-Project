import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import whois
from datetime import datetime
import math
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from sys import stdout
import sys


INITIAL_COLUMNS = [
    'URL',                   # Original URL
    'length',                # URL length
    'num_dots',              # Number of dots in URL
    'num_hyphens',           # Number of hyphens in URL
    'num_slashes',           # Number of slashes in URL
    'num_subdomains',        # Number of subdomains
    'long_url',              # Binary flag: is URL long?
    'path_depth',            # Path depth (non-empty segments)
    'domain_length',         # Domain length
    'contains_ip',           # Whether an IP address is found in URL
    'https_token',           # Whether URL starts with "https://"
    'contains_at_symbol',    # Whether URL contains '@'
    'at_symbol_position',    # Position-based indicator for '@'
    'double_slash_redirecting',  # Multiple occurrences of "//"
    'prefix_suffix',         # Presence of '-' in domain
    'non_standard_port',     # Non-standard port usage
    'shortening_service',    # Whether domain is a known URL shortener
    'num_query_params',      # Number of query parameters
    'query_length',          # Length of query string
    'query_entropy',         # Shannon entropy of query string
    'digit_ratio',           # Ratio of digits in URL
    'suspicious_words',      # Presence of suspicious words (login, verify, etc.)
    'suspicious_extension',  # Whether URL ends with suspicious extension
    'unusual_tld',           # Whether domain TLD is unusual
    'domain_age',            # Domain age (from WHOIS; default -1)
    'domain_registration_length',  # Registration length (default -1)
    'redirection',           # Multiple redirections indicator
    'domain_entropy',        # Shannon entropy of domain name
    'contains_underscore',   # Whether domain contains an underscore
    'subdomain_complexity'   # Complexity flag based on subdomain count
]




def calculate_entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def redirection_check(url):
    positions = [i for i in range(len(url)) if url.startswith('//', i)]
    return 1 if len(positions) > 1 and positions[1] > 5 else -1

def at_symbol_position(url):
    pos = url.find('@')
    return 1 if pos > 0 else -1

def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        today = datetime.today()
        age = (today - creation_date).days if creation_date else -1
        registration_length = (expiration_date - creation_date).days if creation_date and expiration_date else -1
        return {'age': age, 'registration_length': registration_length}
    except Exception as e:
        return {'age': -1, 'registration_length': -1}

def extract_url_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path

    features['length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_subdomains'] = domain.count('.')
    features['long_url'] = 1 if len(url) > 54 else -1
    features['path_depth'] = len([seg for seg in path.split('/') if seg])
    features['domain_length'] = len(domain)
    features['contains_ip'] = 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url) else 0
    features['https_token'] = 1 if url.startswith('https://') else -1
    features['contains_at_symbol'] = 1 if '@' in url else -1
    features['at_symbol_position'] = at_symbol_position(url)
    features['double_slash_redirecting'] = 1 if url.count('//') > 1 else -1
    features['prefix_suffix'] = 1 if '-' in domain else -1

    port = parsed.port
    features['non_standard_port'] = 1 if port and port not in [80, 443] else -1
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
    features['shortening_service'] = 1 if any(service in domain for service in shortening_services) else -1

    query = parsed.query
    query_params = parse_qs(query)
    features['num_query_params'] = len(query_params)
    features['query_length'] = len(query)
    features['query_entropy'] = calculate_entropy(query)
    digits = sum(c.isdigit() for c in url)
    features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update']
    features['suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else -1
    suspicious_extensions = ['.exe', '.zip', '.scr', '.bat']
    features['suspicious_extension'] = 1 if any(url.lower().endswith(ext) for ext in suspicious_extensions) else -1
    tld = domain.split('.')[-1]
    common_tlds = ['com', 'org', 'net', 'edu']
    features['unusual_tld'] = 1 if tld not in common_tlds else -1

    # WHOIS-based features are set to default for speed; uncomment to use actual WHOIS info
    domain_info = get_domain_info(url)
    features['domain_age'] = domain_info.get('age', -1)
    features['domain_registration_length'] = domain_info.get('registration_length', -1)
    

    features['redirection'] = redirection_check(url)
    features['domain_entropy'] = calculate_entropy(domain)
    features['contains_underscore'] = 1 if '_' in domain else -1
    features['subdomain_complexity'] = 1 if domain.count('.') > 2 else -1

    return features

def preprocess_url_dataset(csv_path, output_csv, max_workers=10, batch_size=50000):
    df = pd.read_csv(csv_path)
    url_list = df['URL'].tolist()
    total_urls = len(url_list)

    print(f"Processing {total_urls} URLs...")

    # Initialize output CSV with headers
    pd.DataFrame(columns=INITIAL_COLUMNS).to_csv(output_csv, index=False)

    completed = 0
    features_list = []
    final_df = pd.DataFrame()

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {executor.submit(extract_url_features, url): idx for idx, url in enumerate(url_list)}

        for future in tqdm(as_completed(future_to_index), total=total_urls, desc="Processing URLs", file=sys.stdout):
            try:
                feature_dict = future.result()
                features_list.append(feature_dict)
            except Exception as e:
                print(f"Error processing URL: {e}", flush=True)

            completed += 1

            # Print progress every 1,000 URLs
            if completed % 1000 == 0:
                print(f"Processed {completed}/{total_urls} URLs", flush=True)

            # Write batch to CSV and keep updating `final_df`
            if len(features_list) >= batch_size:
                batch_df = pd.DataFrame(features_list)
                batch_df = batch_df.reindex(columns=INITIAL_COLUMNS)
                batch_df.to_csv(output_csv, mode='a', index=False, header=False)
                final_df = pd.concat([final_df, batch_df], ignore_index=True)  # Store in final DataFrame
                features_list.clear()  # Free memory

        # Write remaining data
        if features_list:
            batch_df = pd.DataFrame(features_list)
            batch_df = batch_df.reindex(columns=INITIAL_COLUMNS)
            batch_df.to_csv(output_csv, mode='a', index=False, header=False)
            final_df = pd.concat([final_df, batch_df], ignore_index=True)

    print(f"✅ Processing complete! Data saved to {output_csv}")
    return final_df  # Return the final DataFrame

if __name__ == "__main__":
    csv_path = "data/combined_dataset.csv"
    output_csv = "data/processed_urls.csv"
    #processed_df = preprocess_url_dataset(csv_path, output_csv, max_workers=20, batch_size=50000)
    print("Processed URL Dataset:")
    #print(processed_df.head(), flush=True)

    test_url = "https://www.angelfire.com/goth/devilmaycrytonite/"
    test_features = extract_url_features(test_url)
    print("Features for test URL:", flush=True)
    print(test_features, flush=True)
