import re
import math
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import whois
import pandas as pd

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

# Examples
#(get_domain_simple("linkedin.com/directory/people/winnick-2.html"))          # linkedin.com
#print(get_domain_simple("https://www.linkedin.com/in/johndoe"))                   # linkedin.com
#print(get_domain_simple("http://sub.domain.example.co.uk/path?query=1"))          # domain.example.co.uk



url = "linkedin.com/directory/people/winnick-2.html"
def get_web_traffic_feature(url):
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
print (get_web_traffic_feature(url))


