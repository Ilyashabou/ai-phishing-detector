import pandas as pd
import re
from sklearn.model_selection import train_test_split
import os
from urllib.parse import urlparse
import socket
try:
    import whois
except ImportError:
    print("Warning: python-whois not found. Domain age features will be disabled.")
    whois = None
from datetime import datetime
import csv

# Define a list of common legitimate domains for fallback
COMMON_LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com', 
    'linkedin.com', 'github.com', 'apple.com', 'microsoft.com', 'amazon.com',
    'netflix.com', 'spotify.com', 'yahoo.com', 'wikipedia.org', 'reddit.com',
    'ebay.com', 'twitch.tv', 'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com',
    'stackoverflow.com', 'medium.com', 'quora.com', 'pinterest.com', 'dropbox.com',
    'zoom.us', 'slack.com', 'salesforce.com', 'adobe.com', 'python.org',
    'github.io', 'wordpress.com', 'blogger.com', 'tumblr.com', 'mozilla.org',
    'office.com', 'outlook.com', 'live.com', 'hotmail.com', 'gmail.com'
}

# Load top 1 million domains into a set for efficient lookup
TOP_1M_DOMAINS = set()
try:
    # First try to load from the expected path
    top1m_path = 'data/raw/top-1m.csv'
    
    if os.path.exists(top1m_path):
        with open(top1m_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 1:  # Ensure there's at least a domain in the row
                    TOP_1M_DOMAINS.add(row[1].lower())
    else:
        print(f"Warning: '{top1m_path}' not found. Using fallback common domains list.")
        # Add common domains as a fallback
        TOP_1M_DOMAINS = COMMON_LEGITIMATE_DOMAINS
except Exception as e:
    print(f"Warning: Could not load top-1m.csv: {e}")
    # Add common domains as a fallback
    TOP_1M_DOMAINS = COMMON_LEGITIMATE_DOMAINS

KNOWN_DOMAIN_AGES = {
    'google.com': 9000,  # Approx days since registration
    'github.com': 5000,
    'facebook.com': 7000,
    # Add more common domains
}

def normalize_url(url):
    """
    Normalize URL by:
    1. Converting to lowercase
    2. Removing protocol (http://, https://)
    3. Removing www. prefix
    4. Removing trailing slashes
    5. Handling edge cases (empty, malformed URLs)
    """
    if not isinstance(url, str):
        return None
        
    url = str(url).lower().strip()
    
    # Remove protocol
    url = re.sub(r'^https?://', '', url)
    
    # Remove www. prefix
    url = re.sub(r'^www\.', '', url)
    
    # Remove trailing slashes
    url = url.rstrip('/')
    
    # Handle empty or malformed URLs
    if not url or len(url) < 3:  # Minimum length for a valid domain
        return None
        
    return url

def is_valid_ip(ip_str):
    """Check if a string is a valid IP address"""
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False

def get_domain_age_days(domain):
    """Get domain age in days from WHOIS information with network error handling"""
    try:
        if whois is None:
            return 0
            
        # Add timeout to prevent long waits
        w = whois.whois(domain, timeout=5)
        
        # Handle different date formats and multiple dates
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Calculate days since creation
            days_old = (datetime.now() - creation_date).days
            return max(0, days_old)  # Ensure non-negative
    except (socket.timeout, socket.error):
        print(f"Network error during WHOIS lookup for {domain}")
    except Exception as e:
        pass
    
    return 0  # Default if unable to determine

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        
        # Handle URLs without protocol
        parts = url.split('/', 1)
        if len(parts) > 0:
            return parts[0].split('?', 1)[0].split('#', 1)[0]
        
    except:
        pass
    
    return ""

def extract_features(url):
    """
    Extract features from URL with improved edge case handling:
    1. URL length
    2. Number of dots
    3. Has HTTPS
    4. Number of hyphens
    5. Number of subdirectories
    6. Has IP address
    7. Has suspicious words
    8. Domain length
    9. Number of digits
    10. Has special characters
    11. Domain in top 1 million
    12. Domain age in days
    13. Has login-related keywords
    14. Has suspicious TLD
    """
    if not url:
        return pd.Series({
            'url_length': 0,
            'num_dots': 0,
            'has_https': 0,
            'num_hyphens': 0,
            'num_subdirs': 0,
            'has_ip': 0,
            'suspicious_word': 0,
            'domain_length': 0,
            'num_digits': 0,
            'has_special_chars': 0,
            'domain_in_top1m': 0,
            'whois_days_old': 0,
            'has_login_keyword': 0,
            'tld_suspicious': 0,
            'phishing_signals': 0
        })
    
    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
    except:
        domain = ""
    
    # Basic features
    url_length = len(url)
    num_dots = url.count('.')
    has_https = int('https://' in url.lower())
    num_hyphens = url.count('-')
    num_subdirs = url.count('/')
    
    # Number of digits
    num_digits = sum(c.isdigit() for c in url)
    
    # IP address detection
    has_ip = 0
    try:
        has_ip = int(is_valid_ip(domain))
    except:
        pass
    
    # Suspicious words (general)
    suspicious_words = [
        'secure', 'account', 'update', 'free',
        'lucky', 'bonus', 'verify', 'confirm', 'password',
        'bank', 'paypal', 'amazon', 'ebay', 'apple'
    ]
    suspicious_word = int(any(word in url.lower() for word in suspicious_words))
    
    # Login-related keywords (specific)
    login_words = [
        'login', 'signin', 'logon', 'secure', 'security',
        'update', 'authenticate', 'verification', 'identity',
        'access', 'admin', 'recover', 'password', 'credential'
    ]
    has_login_keyword = int(any(word in url.lower() for word in login_words))
    
    # Domain length
    domain_length = len(domain)
    
    # Special characters
    has_special_chars = int(bool(re.search(r'[!@#$%^&*()":{}|<>]', url)))
    
    # Domain in top 1 million sites
    domain_in_top1m = 0
    try:
        # Extract domain and normalize it
        domain_only = extract_domain(url).lower()
        
        # Remove www. prefix
        if domain_only.startswith('www.'):
            domain_only = domain_only[4:]
            
        # Check for exact match or suffix match
        if domain_only in TOP_1M_DOMAINS:
            domain_in_top1m = 1
        else:
            # Check for domain.com when subdomain.domain.com is provided
            parts = domain_only.split('.')
            if len(parts) > 2:
                main_domain = '.'.join(parts[-2:])  # e.g., extract google.com from maps.google.com
                if main_domain in TOP_1M_DOMAINS or main_domain in COMMON_LEGITIMATE_DOMAINS:
                    domain_in_top1m = 1
    except:
        pass
    
    # Domain age in days
    whois_days_old = 0
    if domain and not has_ip:
        try:
            whois_days_old = get_domain_age_days(domain)
        except:
            pass
    
    # Suspicious TLD
    tld_suspicious = 0
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'racing', 'party']
    if domain and '.' in domain:
        tld = domain.split('.')[-1].lower()
        tld_suspicious = int(tld in suspicious_tlds)
    
    # Calculate phishing signals score
    phishing_signals = (
        has_ip * 3 + 
        tld_suspicious * 2 + 
        has_special_chars + 
        has_login_keyword - 
        domain_in_top1m * 5  # Strong negative weight for known domains
    )
    
    result = pd.Series({
        'url_length': url_length,
        'num_dots': num_dots,
        'has_https': has_https,
        'num_hyphens': num_hyphens,
        'num_subdirs': num_subdirs,
        'has_ip': has_ip,
        'suspicious_word': suspicious_word,
        'domain_length': domain_length,
        'num_digits': num_digits,
        'has_special_chars': has_special_chars,
        'domain_in_top1m': domain_in_top1m,
        'whois_days_old': whois_days_old,
        'has_login_keyword': has_login_keyword,
        'tld_suspicious': tld_suspicious,
        'phishing_signals': phishing_signals
    })
    
    return result

def normalize_dataset(df, url_column, label_value=None, label_column=None):
    """
    Normalize dataset with improved error handling:
    1. Handle missing columns
    2. Handle invalid URLs
    3. Handle missing labels
    4. Handle case sensitivity in labels
    """
    try:
        # Create a copy with URL and label columns
        if label_column is not None:
            if label_column not in df.columns:
                raise ValueError(f"Label column '{label_column}' not found in dataset")
            df = df[[url_column, label_column]].copy()
        else:
            df = df[[url_column]].copy()
        
        # Normalize URLs
        df['url'] = df[url_column].apply(normalize_url)
        
        # Remove rows with invalid URLs
        df = df[df['url'].notna()]
        
        # Handle labeling
        if label_column is not None:
            df['label'] = df[label_column].str.lower().apply(
                lambda x: 1 if x == 'phishing' else 0 if x == 'legitimate' else None
            )
            # Remove rows with invalid labels
            df = df[df['label'].notna()]
        else:
            df['label'] = label_value
        
        return df[['url', 'label']]
    except Exception as e:
        print(f"Error normalizing dataset: {str(e)}")
        return pd.DataFrame(columns=['url', 'label'])

def main():
    # Ensure output directory exists
    os.makedirs('data/processed', exist_ok=True)
    
    try:
        print("Loading datasets...")
        # Load datasets with appropriate labeling
        phishing_urls = pd.read_csv('data/raw/Phishing URLs.csv')
        top_1m = pd.read_csv('data/raw/top-1m.csv', names=['rank', 'url'])
        url_dataset = pd.read_csv('data/raw/URL dataset.csv')
        verified_online = pd.read_csv('data/raw/verified_online.csv')
        
        print("Normalizing datasets...")
        # Normalize each dataset
        phishing_df = normalize_dataset(phishing_urls, 'url', label_column='Type')
        legitimate_df = normalize_dataset(top_1m, 'url', label_value=0)
        url_dataset_df = normalize_dataset(url_dataset, 'url', label_column='type')
        verified_df = normalize_dataset(verified_online, 'url', label_value=1)
        
        print("Combining datasets...")
        # Combine all datasets
        combined_df = pd.concat([
            phishing_df,
            legitimate_df,
            url_dataset_df,
            verified_df
        ], ignore_index=True)
        
        print("Removing duplicates...")
        # Remove duplicates based on normalized URLs
        combined_df = combined_df.drop_duplicates(subset=['url'])
        
        print("Extracting features...")
        # Extract features
        features_df = combined_df['url'].apply(extract_features)
        final_df = pd.concat([combined_df, features_df], axis=1)
        
        print("Splitting into train/test sets...")
        # Split into train/test sets
        train_df, test_df = train_test_split(
            final_df,
            test_size=0.2,
            stratify=final_df['label'],
            random_state=42
        )
        
        print("Saving processed datasets...")
        # Save processed datasets
        train_df.to_csv('data/processed/train.csv', index=False)
        test_df.to_csv('data/processed/test.csv', index=False)
        
        print("\n✅ Processing complete!")
        print(f"Train set shape: {train_df.shape}")
        print(f"Test set shape: {test_df.shape}")
        print(f"Features: {list(final_df.columns)}")
        print(f"Class distribution in train set:\n{train_df['label'].value_counts(normalize=True)}")
        print(f"Class distribution in test set:\n{test_df['label'].value_counts(normalize=True)}")
        
    except Exception as e:
        print(f"❌ Error processing datasets: {str(e)}")

if __name__ == "__main__":
    main()
