import re
import math
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime
import whois
import pandas as pd

def calculate_entropy(s):
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in prob)

def get_web_traffic_feature(url):
    """
    Retrieve the web traffic feature based on the site's rank.
    According to the documentation:
      - IF website rank < 100,000 → Legitimate (feature = 1)
      - IF website rank > 100,000 → Suspicious (feature = 0)
      - Otherwise (or if unavailable) → Phishing (feature = -1)
    """
    try:
        domain = get_domain_simple(url)
        response = requests.get(f"https://siterank.redirect2.me/api/rank.json?domain={domain}")
        data = response.json()
        rank = data.get('rank')
        if rank is None:
            return -1
        elif rank < 100000:
            return 1
        else:
            return 0
    except Exception as e:
        print(f"Error in get_web_traffic_feature: {e}")
        return -1
    
def get_domain_simple(url: str) -> str:
    """
    Gracefully extract the domain from any URL-like string by:
      1. Prepending 'http://' if missing a scheme.
      2. Parsing via urlparse to get netloc.
      3. Stripping port numbers and 'www.' prefix.
    """
    raw_url = url.strip()
    if not raw_url.lower().startswith(('http://', 'https://')):
        raw_url = 'http://' + url  # ensure urlparse.netloc is populated :contentReference[oaicite:2]{index=2}
    
    parsed = urlparse(raw_url)      # parse URL into components :contentReference[oaicite:3]{index=3}
    domain = parsed.netloc

    # Remove port if present
    if ':' in domain:
        domain = domain.split(':', 1)[0]  # strip ":443", etc. :contentReference[oaicite:4]{index=4}

    # Remove "www." if present
    if domain.lower().startswith('www.'):
        domain = domain[4:]
    return domain



def get_favicon_feature(url):
    """
    Rule: IF favicon is loaded from an external domain → Phishing (-1)
          OTHERWISE → Legitimate (1)
    """
    # Ensure URL has a scheme
    if not url.startswith(('http://','https://')):
        url = 'https://' + url

    # Parse page domain
    parsed = urlparse(url)
    page_domain = parsed.netloc.lower()

    try:
        # Fetch and parse HTML
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')  # :contentReference[oaicite:0]{index=0}

        # Find any <link rel="icon"> or shortcut icon
        icon_link = soup.find(
            'link',
            attrs={'rel': lambda r: r and 'icon' in r.lower()}
        )
        if icon_link and icon_link.get('href'):
            icon_href = icon_link['href']
            # Resolve relative URLs
            icon_url = urljoin(url, icon_href)                  # :contentReference[oaicite:1]{index=1}
        else:
            # Fallback to default /favicon.ico
            icon_url = f"{parsed.scheme}://{page_domain}/favicon.ico"

        # Compare domains
        icon_domain = urlparse(icon_url).netloc.lower()
        return -1 if icon_domain != page_domain else 1

    except Exception:
        # On any error (network/parse), conservatively assume external → phishing
        return -1





def extract_30_features(url):
    """
    Extract phishing-related features from the given URL based on the documentation.
    For each feature, the value is set as:
      1 → Legitimate
      0 → Suspicious
     -1 → Phishing
    """
    features = {}
    parsed = urlparse(url)
    domain = get_domain_simple(url)
    
    # 1. Using the IP Address
    features['having_IP_Address'] = -1 if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain) else 1
    
    # 2. Long URL to Hide the Suspicious Part
    url_length = len(url)
    if url_length < 54:
        features['URL_Length'] = 1
    elif 54 <= url_length <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = -1

    # 3. Using URL Shortening Services (e.g. TinyURL)
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
    features['Shortening_Service'] = -1 if any(s in domain for s in shorteners) else 1

    # 4. URL’s having “@” Symbol
    features['having_At_Symbol'] = -1 if '@' in url else 1

    # 5. Redirecting using “//”
    last_double_slash = url.rfind("//")
    expected_position = 7 if url.startswith("https://") else 6
    features['double_slash_redirecting'] = -1 if last_double_slash > expected_position else 1

    # 6. Adding Prefix or Suffix Separated by (-) to the Domain
    features['Prefix_Suffix'] = -1 if '-' in domain else 1

    # 7. Sub Domain and Multi Sub Domains
    dot_count = domain.count('.')
    if dot_count == 1:
        features['having_Sub_Domain'] = 1
    elif dot_count == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = -1

    # 8. HTTPS (Secure) Protocol
    features['SSLfinal_State'] = 1 if url.startswith('https://') else -1

    # 9. Website Traffic
    features['web_traffic'] = get_web_traffic_feature(url)

    # 10. Domain Registration Length & Age of Domain
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        if creation_date and expiration_date:
            reg_length = (expiration_date - creation_date).days
            features['Domain_registration_length'] = 1 if reg_length > 365 else -1
            age = (datetime.now() - creation_date).days
            features['age_of_domain'] = 1 if age >= 180 else -1  # using 6 months threshold
        else:
            features['Domain_registration_length'] = -1
            features['age_of_domain'] = -1
    except Exception as e:
        print(f"WHOIS lookup error: {e}")
        features['Domain_registration_length'] = -1
        features['age_of_domain'] = -1

    # 11. Favicon
    features['Favicon'] = get_favicon_feature(url)

    # 12. Using Non-Standard Port
    if parsed.port and parsed.port not in [80, 443]:
        features['port'] = -1
    else:
        features['port'] = 1

    # 13. Existence of “HTTPS” Token in the Domain Part of the URL
    features['HTTPS_token'] = -1 if 'https' in domain else 1

    # Web scraping based features:
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 14. Request URL (External objects in the webpage)
            all_tags = soup.find_all(['img', 'script', 'link'])
            total_tags = len(all_tags)
            external_tags = 0
            for tag in all_tags:
                src = tag.get('src', '')
                if src and domain not in src:
                    external_tags += 1
            ratio = external_tags / (total_tags + 1)
            if ratio < 0.22:
                features['Request_URL'] = 1
            elif 0.22 <= ratio <= 0.61:
                features['Request_URL'] = 0
            else:
                features['Request_URL'] = -1

            # 15. URL of Anchor (external anchor links)
            anchor_tags = soup.find_all('a', href=True)
            total_anchors = len(anchor_tags)
            external_anchors = 0
            for a in anchor_tags:
                href = a.get('href', '')
                if href and domain not in href:
                    external_anchors += 1
            anchor_ratio = external_anchors / (total_anchors + 1)
            if anchor_ratio < 0.31:
                features['URL_of_Anchor'] = 1
            elif 0.31 <= anchor_ratio <= 0.67:
                features['URL_of_Anchor'] = 0
            else:
                features['URL_of_Anchor'] = -1

            # 16. Links in <Meta>, <Script> and <Link> tags
            meta_script_link = soup.find_all(['meta', 'script', 'link'])
            total_meta_script_link = len(meta_script_link)
            all_tags_total = len(soup.find_all())
            ratio_meta = total_meta_script_link / (all_tags_total + 1)
            if ratio_meta < 0.17:
                features['Links_in_tags'] = 1
            elif 0.17 <= ratio_meta <= 0.81:
                features['Links_in_tags'] = 0
            else:
                features['Links_in_tags'] = -1

            # 17. Server Form Handler (SFH)
            forms = soup.find_all('form', action=True)
            if forms:
                sfh_scores = []
                for form in forms:
                    action = form.get('action', '').strip().lower()
                    if action == "" or action == "about:blank":
                        sfh_scores.append(-1)
                    else:
                        action_domain = urlparse(action).netloc.lower()
                        if action_domain == "" or domain in action_domain:
                            sfh_scores.append(1)
                        else:
                            sfh_scores.append(0)
                features['SFH'] = int(round(sum(sfh_scores) / len(sfh_scores)))
            else:
                features['SFH'] = 1

            # 18. Submitting Information to Email
            email_submission = any('mailto:' in form.get('action', '').lower() for form in forms)
            features['Submitting_to_email'] = -1 if email_submission else 1

            # 19. Abnormal URL
            features['Abnormal_URL'] = -1 if domain not in url else 1

            # 20. Status Bar Customization (onMouseOver)
            features['on_mouseover'] = -1 if 'onmouseover' in response.text.lower() else 1

            # 21. Disabling Right Click
            features['RightClick'] = -1 if 'contextmenu' in response.text.lower() else 1

            # 22. Using Pop-up Window
            features['popUpWindow'] = -1 if 'window.open' in response.text.lower() else 1

            # 23. IFrame Redirection
            features['Iframe'] = -1 if '<iframe' in response.text.lower() else 1
    except Exception as e:
        print(f"Error during web scraping: {e}")
        for key in ['Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
                    'Submitting_to_email', 'Abnormal_URL', 'on_mouseover',
                    'RightClick', 'popUpWindow', 'Iframe']:
            features[key] = -1

    # 24. DNS Record
    try:
        features['DNSRecord'] = 1 if whois.whois(domain) else -1
    except Exception as e:
        print(f"DNS record error: {e}")
        features['DNSRecord'] = -1

    # 25. PageRank (Not implemented; placeholder)
    features['Page_Rank'] = -1

    # 26. Google Index
    features['Google_Index'] = 1

    # 27. Number of Links Pointing to Page
    features['Links_pointing_to_page'] = 1

    # 28. Statistical Report Based Feature (Not implemented; placeholder)
    features['Statistical_report'] = -1

    # 29. Redirect Attribute
    features['Redirect'] = extract_redirect_attribute(url)

    return features

def extract_redirect_attribute(url):
    """
    Extracts the 'Redirect' attribute from the URL.
    
    For this feature:
      - 1 if the URL query string contains a 'redirect' parameter,
      - 0 otherwise.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for key in query_params:
        if 'redirect' in key.lower():
            return 1
    return 0

if __name__ == "__main__":
    # Test with an example URL
    test_url = "linkedin.com/directory/people/winnick-2.html"
    features = extract_30_features(test_url)
    print("Extracted Features:")
    for key, value in features.items():
        print(f"{key}: {value}")
    df_test = pd.DataFrame([features])
    print(df_test.head())    
    
    # Test the Redirect attribute extraction
    