import pandas as pd
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from src.url_feature_extractor import extract_features

# Create a simple test model with the new features
print("Creating test model with all features...")
feature_names = [
    'url_length', 'num_dots', 'has_https', 'num_hyphens', 'num_subdirs', 
    'has_ip', 'suspicious_word', 'domain_length', 'num_digits', 'has_special_chars'
]

# Create a simple dummy model
X = np.random.rand(100, len(feature_names))
y = np.random.randint(0, 2, 100)
model = LogisticRegression(max_iter=1000, class_weight='balanced')
model.fit(X, y)

# Save model and feature names
print("Saving model and feature names...")
joblib.dump(model, 'models/phishing_model.pkl')
joblib.dump(feature_names, 'models/feature_names.pkl')

# Test feature extraction
print("\nTesting feature extraction...")
test_url = "https://www.example.com/login?user=123"
features = extract_features(test_url)

print(f"URL: {test_url}")
print("\nExtracted features as Series object:")
print(features)

print("\nFeature values (dictionary format):")
for feature in feature_names:
    if feature in features:
        print(f"  - {feature}: {features.get(feature, 'MISSING')}")
    else:
        print(f"  - {feature}: MISSING")

print("\nModel and feature names saved successfully!")
print("You can now run the predict.py script to test real URLs.") 