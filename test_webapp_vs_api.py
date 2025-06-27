import sys
import os
sys.path.append(os.path.abspath('.'))
import joblib
from src.url_feature_extractor import extract_features
import pandas as pd

print('Loading model...')
model = joblib.load('models/phishing_model.pkl')
feature_names = joblib.load('models/feature_names.pkl')

test_urls = [
    'https://google.com',
    'https://facebook.com',
    'https://amazon.com',
    'http://suspicious-site.tk/login',
    'http://192.168.1.1/login.php',
    'http://amaz0n-secure.com/signin'
]

print('\nSimulating Web App Processing:')
for url in test_urls:
    # Extract features
    features = extract_features(url)
    
    # Ensure features match what was used in training
    if feature_names is not None:
        features = features.reindex(feature_names, fill_value=0)
    
    # Convert to DataFrame for prediction
    features_df = pd.DataFrame([features])
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    # Get confidence score if available
    confidence = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features_df)[0][1]  # Probability of class 1 (Phishing)
        confidence = proba if result == "Phishing" else 1-proba
    
    print(f'Web App - {url}: {result} (Confidence: {confidence:.2f})')

print('\nSimulating API Processing:')
for url in test_urls:
    # Extract features
    features = extract_features(url)
    
    # Ensure features match what was used in training
    if feature_names is not None:
        features = features.reindex(feature_names, fill_value=0)
    
    # Convert to DataFrame for prediction
    features_df = pd.DataFrame([features])
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    # Convert numpy.int64 to Python int
    prediction = int(prediction)
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    # Get confidence score if available
    confidence = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features_df)[0][1]  # Probability of class 1 (Phishing)
        # Convert numpy.float64 to Python float
        confidence = float(proba) if result == "Phishing" else float(1-proba)
    
    print(f'API - {url}: {result} (Confidence: {confidence:.2f})')

# Print the phishing_signals value for each URL
print('\nPhishing Signals Values:')
for url in test_urls:
    features = extract_features(url)
    print(f'{url}: {features["phishing_signals"]}')