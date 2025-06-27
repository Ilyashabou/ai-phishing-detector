import sys
import os
sys.path.append(os.path.abspath('.'))
import joblib
from src.url_feature_extractor import extract_features
import pandas as pd

print('Loading model...')
model = joblib.load('models/phishing_model.pkl')
feature_names = joblib.load('models/feature_names.pkl')

test_urls = ['https://google.com', 'https://facebook.com', 'https://amazon.com']
print('Testing legitimate URLs:')
for url in test_urls:
    features = extract_features(url)
    features = features.reindex(feature_names, fill_value=0)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    result = 'Phishing' if prediction == 1 else 'Legitimate'
    print(f'{url}: {result}')

print('\nTesting suspicious URLs:')
suspicious_urls = ['http://suspicious-site.tk/login', 'http://192.168.1.1/login.php', 'http://amaz0n-secure.com/signin']
for url in suspicious_urls:
    features = extract_features(url)
    features = features.reindex(feature_names, fill_value=0)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    result = 'Phishing' if prediction == 1 else 'Legitimate'
    print(f'{url}: {result}')