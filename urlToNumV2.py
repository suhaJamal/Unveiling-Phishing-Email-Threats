from urllib.parse import urlparse, urljoin

import pandas as pd
import requests, socket, ssl, whois
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

# Helper function for fetching and parsing HTML content
def fetch_and_parse_html(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser')
    except requests.RequestException:
        return None

# Helper function for calculating percentage
def calculate_percentage(part, total):
    return (part / total) * 100 if total else 0

def get_domain(url):
    return urlparse(url).netloc

def has_ip_address(url):
    domain = get_domain(url)
    try:
        socket.inet_aton(domain)
        return -1
    except socket.error:
        return 1

def check_ssl_trust(url):
    domain = get_domain(url)
    if not domain:
        return -1

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()
                if cert:
                    return 1#, "Valid SSL"
                else:
                    return -1#, "No SSL cert retrieved"
    except ssl.CertificateError as e:
        return -1#, f"Certificate error: {str(e)}"
    except ssl.SSLError as e:
        return -1#, f"SSL error: {str(e)}"
    except socket.timeout:
        return -1#, "Connection timed out"
    except socket.error as e:
        return -1#, f"Socket error: {str(e)}"
    except Exception as e:
        return -1#, f"Other error: {str(e)}"

def check_url_of_anchor(url):
    soup = fetch_and_parse_html(url)
    if soup:
        try:
            total_tags = len(soup.find_all())
            anchor_tags = len(soup.find_all('a'))
            if total_tags > 0:
                percentage_of_anchor = calculate_percentage(anchor_tags, total_tags)
                return 1 if percentage_of_anchor < 31 else 0 if percentage_of_anchor <= 67 else -1
        except Exception as e:
            print(f"Error in check_url_of_anchor for URL {url}: {e}")
    return 0  # Return 0 if an error occurs

def check_links_in_tags(url):
    soup = fetch_and_parse_html(url)
    if soup:
        try:
            specific_tags_count = sum(len(soup.find_all(tag)) for tag in ['meta', 'script', 'link'])
            total_tags = len(soup.find_all())
            if total_tags > 0:
                percentage_of_specific_tags = calculate_percentage(specific_tags_count, total_tags)
                return 1 if percentage_of_specific_tags < 17 else 0 if percentage_of_specific_tags <= 81 else -1
        except Exception as e:
            print(f"Error in check_links_in_tags for URL {url}: {e}")
    return 0  # Return 0 if an error occurs

def classify_url_by_length(url):
    length = len(url)
    return 1 if length < 54 else 0 if length <= 75 else -1

def is_shortened_url(url):
    domain = get_domain(url)
    return -1 if domain in ['tinyurl.com', 'bit.ly', 'goo.gl', 't.co', 'ow.ly'] else 1

def has_dns_record(url):
    try:
        socket.getaddrinfo(get_domain(url), None)
        return 1
    except socket.gaierror:
        return -1

def check_domain_age(url):
    try:
        creation_date = whois.whois(get_domain(url)).creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return 1 if creation_date and creation_date < datetime.now() - timedelta(days=6*30) else -1
    except Exception:
        return -1

def classify_domain_by_dots(url):
    domain = get_domain(url).lstrip('www.')
    return 1 if domain.count('.') == 1 else 0 if domain.count('.') == 2 else -1

def classify_url_by_request_percentage(url):
    parsed_url = urlparse(url)
    request_url_length = len(parsed_url.path + parsed_url.query + parsed_url.fragment)
    total_length = len(url)
    percentage_of_request_url = calculate_percentage(request_url_length, total_length)
    return 1 if percentage_of_request_url < 22 else 0 if 22 <= percentage_of_request_url <= 61 else -1

def check_domain_hyphen(url):
    return -1 if '-' in get_domain(url) else 1

def check_domain_expiration(url):
    try:
        expiration_date = whois.whois(get_domain(url)).expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return -1 if expiration_date and expiration_date <= datetime.now() + timedelta(days=120) else 1
    except Exception:
        return -1

def classify_sfh(url):
    try:
        soup = fetch_and_parse_html(url)
        if not soup:
            return -1
        for form in soup.find_all('form'):
            action = form.get('action', '').strip()
            if not action or action == 'about:blank':
                return -1
            full_action_url = urljoin(url, action)
            if get_domain(url) != get_domain(full_action_url):
                return 0
        return 1  # Legitimate if no issues found
    except Exception:
        return -1  # Return -1 in case of any exceptions

def check_http_in_domain(url):
    return -1 if 'http' in get_domain(url) else 1

def check_at_symbol_in_url(url):
    return -1 if '@' in url else 1

# Keep the features dictionary as is
features = {
    'having_IPhaving_IP_Address': has_ip_address,
    'SSLfinal_State': check_ssl_trust,
    'URL_of_Anchor': check_url_of_anchor,
    'Links_in_tags': check_links_in_tags,
    'having_Sub_Domain': classify_domain_by_dots,
    'Request_URL': classify_url_by_request_percentage,
    'Prefix_Suffix': check_domain_hyphen,
    'Domain_registeration_length': check_domain_expiration,
    'SFH': classify_sfh,
    'HTTPS_token': check_http_in_domain,
    'having_At_Symbol': check_at_symbol_in_url,
    'URLURL_Length': classify_url_by_length,
    'Shortining_Service': is_shortened_url
}

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        # Check if the scheme and netloc (domain) are present
        return len(parsed.scheme) > 0 and len(parsed.netloc) > 0
    except ValueError:
        return False
    
def prepare_URL(url_to_check):

    if not is_valid_url(url_to_check):
        #print(f"Invalid URL: {url_to_check}")
        # If the URL is invalid, return a DataFrame filled with -1
        # Assuming you know the number of features you are testing (e.g., 13 features)
        feature_values = [-1] * len(features)  # 'features' should be the dictionary containing all feature functions
        #print(feature_values)
        column_names = list(features.keys())
        features_df = pd.DataFrame([feature_values], columns=column_names)
        return features_df
    
    # Create a local copy of features for processing
    local_features = features.copy()  # Make a shallow copy of the dictionary

    for feature, function in local_features.items():
        try:
            local_features[feature] = function(url_to_check)  # Update the local copy, not the global one
        except Exception as e:
            #print(f"Error processing {feature}: {e}")
            local_features[feature] = -1

    # Convert the values to a DataFrame
    feature_values = list(local_features.values())
    column_names = list(local_features.keys())

    features_df = pd.DataFrame([feature_values], columns=column_names)
    #print(feature_values)
    return features_df

if __name__ == "__main__":
    #url_to_check ="https://www.mycodeclub.io/pages/about-us/"
    #url_to_check = "https://www.mycodeclub.io"
    url_to_check = "http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html"
    #url_to_check = 'http://88.204.202.98/2/paypal.ca/index.html%E2%80%9D'
    prepare_URL(url_to_check)