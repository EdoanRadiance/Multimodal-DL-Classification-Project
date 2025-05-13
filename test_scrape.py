import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from requests.exceptions import RequestException

def normalize_url(u: str) -> str:
    """Ensure the URL has a scheme so urlparse.netloc is populated."""
    u = u.strip()
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    return u

def extract_domain(u: str) -> str:
    """Normalize + parse, strip ports and leading 'www.'"""
    p = urlparse(normalize_url(u))
    dom = p.netloc.split(":", 1)[0].lower()
    return dom[4:] if dom.startswith("www.") else dom

def fetch_soup(u: str) -> BeautifulSoup:
    """Fetch HTML and return BeautifulSoup; raises on network/HTTP errors."""
    r = requests.get(normalize_url(u), timeout=5)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")

def get_favicon_feature(u: str) -> int:
    """
    IF favicon domain ≠ page domain → -1 (phishing)
    ELSE → 1 (legitimate)
    Any error → -1
    """
    try:
        page_url = normalize_url(u)
        page_dom = extract_domain(page_url)

        r = requests.get(page_url, timeout=5)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        icon_tag = soup.find("link", attrs={"rel": lambda r: r and "icon" in r.lower()})
        if icon_tag and icon_tag.get("href"):
            icon_url = urljoin(page_url, icon_tag["href"])
        else:
            # default fallback
            parsed = urlparse(page_url)
            icon_url = f"{parsed.scheme}://{page_dom}/favicon.ico"

        icon_dom = urlparse(icon_url).netloc.split(":", 1)[0].lower()
        return -1 if icon_dom != page_dom else 1

    except Exception:
        return -1

def get_html_features(u: str) -> dict:
    """
    Extracts the 10 HTML/JS–based features.  
    Defaults all to -1 on any RequestException or parsing error.
    """
    defaults = {
        "Request_URL":        -1,
        "URL_of_Anchor":      -1,
        "Links_in_tags":      -1,
        "SFH":                -1,
        "Submitting_to_email":-1,
        "Abnormal_URL":       -1,
        "on_mouseover":       -1,
        "RightClick":         -1,
        "popUpWindow":        -1,
        "Iframe":             -1,
    }

    try:
        dom  = extract_domain(u)
        soup = fetch_soup(u)

        # 14. Request_URL
        tags = soup.find_all(["img", "script", "link"])
        ext  = sum(1 for t in tags if t.get("src", "") and dom not in t["src"])
        r    = ext / (len(tags) + 1)
        defaults["Request_URL"] = 1 if r < 0.22 else (0 if r <= 0.61 else -1)

        # 15. URL_of_Anchor
        anchors = soup.find_all("a", href=True)
        ext_a   = sum(1 for a in anchors if dom not in a["href"])
        ar      = ext_a / (len(anchors) + 1)
        defaults["URL_of_Anchor"] = 1 if ar < 0.31 else (0 if ar <= 0.67 else -1)

        # 16. Links_in_tags
        meta_tags = soup.find_all(["meta", "script", "link"])
        total     = len(soup.find_all())
        mr        = len(meta_tags) / (total + 1)
        defaults["Links_in_tags"] = 1 if mr < 0.17 else (0 if mr <= 0.81 else -1)

        # 17. SFH (Server Form Handler)
        forms = soup.find_all("form", action=True)
        if forms:
            scores = []
            for f in forms:
                action = f["action"].strip().lower()
                if action in ("", "about:blank"):
                    scores.append(-1)
                else:
                    adom = urlparse(normalize_url(action)).netloc.lower()
                    scores.append(1 if (not adom or dom in adom) else 0)
            defaults["SFH"] = round(sum(scores) / len(scores))
        else:
            defaults["SFH"] = 1

        # 18. Submitting_to_email
        defaults["Submitting_to_email"] = -1 if any("mailto:" in f["action"].lower() for f in forms) else 1

        # 19. Abnormal_URL
        defaults["Abnormal_URL"] = -1 if dom not in normalize_url(u) else 1

        # 20–23. JS/iframe checks in page text / structure
        text = soup.get_text().lower()
        defaults["on_mouseover"]   = -1 if "onmouseover" in text else 1
        defaults["RightClick"]     = -1 if "contextmenu" in text else 1
        defaults["popUpWindow"]    = -1 if "window.open" in text else 1
        defaults["Iframe"]         = -1 if soup.find("iframe") else 1

        return defaults

    except RequestException:
        return defaults
    except Exception:
        return defaults

if __name__ == "__main__":
    tests = [
        "news.tigerdirect.com/2010/11/19/pink-friday-2010-to-feature-nicki-minaj/",
        "linkedin.com/directory/people/winnick-2.html",
        "https://linkedin.com/directory/people/winnick-2.html",
    ]
    for url in tests:
        print(f"\nTesting {url!r}")
        print(" favicon:        ", get_favicon_feature(url))
        feats = get_html_features(url)
        for k, v in feats.items():
            print(f" {k:20s}: {v}")
