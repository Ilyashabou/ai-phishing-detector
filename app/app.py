import sys
import os
# Add the parent directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify
import joblib
from src.url_feature_extractor import extract_features  # Feature extraction logic

app = Flask(__name__)

# Define the parent directory path
PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Load trained model and feature names with correct paths
try:
    model = joblib.load(os.path.join(PARENT_DIR, 'models/phishing_model.pkl'))
    print(f"Model loaded successfully from {os.path.join(PARENT_DIR, 'models/phishing_model.pkl')}")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    model = None

try:
    feature_names = joblib.load(os.path.join(PARENT_DIR, 'models/feature_names.pkl'))
except:
    feature_names = None

def format_feature(name, value):
    """Format feature values for display"""
    if name == 'whois_days_old':
        if value == 0:
            return "Unknown"
        elif value < 30:
            return f"{value} days (Very New ⚠️)"
        elif value < 180:
            return f"{value} days (New)"
        else:
            return f"{value} days (Established ✓)"
    
    elif name in ['domain_in_top1m', 'has_https']:
        return "Yes ✓" if value == 1 else "No"
    
    elif name in ['has_ip', 'has_login_keyword', 'suspicious_word', 'tld_suspicious', 'has_special_chars']:
        return "Yes ⚠️" if value == 1 else "No"
    
    return value

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    features_dict = None
    confidence = None
    url = None
    
    if request.method == 'POST':
        url = request.form['url']
        
        if model is None:
            result = "Error: Model not loaded. Please check if the model file exists."
            return render_template('index.html', result=result, url=url)
            
        try:
            # Extract features
            features = extract_features(url)
            
            # Ensure features match what was used in training
            if feature_names:
                # Reindex features to match the expected feature names
                features = features.reindex(feature_names, fill_value=0)
            
            # Convert to DataFrame for prediction
            features_df = pd.DataFrame([features])
            
            # Make prediction
            prediction = model.predict(features_df)[0]
            # Convert numpy.int64 to Python int if needed
            if hasattr(prediction, 'item'):
                prediction = prediction.item()
            result = "Phishing" if prediction == 1 else "Legitimate"
            
            # Get confidence score if available
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(features_df)[0][1]  # Probability of class 1 (Phishing)
                # Convert numpy.float64 to Python float if needed
                if hasattr(proba, 'item'):
                    proba = proba.item()
                confidence = proba if result == "Phishing" else 1-proba
            
            # Prepare features for display
            features_dict = {}
            
            # Group features by category
            security_features = ['has_https', 'has_ip', 'has_special_chars', 'tld_suspicious']
            content_features = ['suspicious_word', 'has_login_keyword']
            reputation_features = ['domain_in_top1m', 'whois_days_old']
            structural_features = ['url_length', 'domain_length', 'num_dots', 'num_hyphens', 'num_subdirs', 'num_digits']
            
            # Organize features by category
            for category, feature_list in [
                ("Security Indicators", security_features),
                ("Content Indicators", content_features),
                ("Reputation Indicators", reputation_features),
                ("Structural Indicators", structural_features)
            ]:
                features_dict[category] = {
                    feature.replace('_', ' ').title(): format_feature(feature, features[feature]) 
                    for feature in feature_list if feature in features
                }
                
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template('index.html', result=result, confidence=confidence, features=features_dict, url=url)

if __name__ == '__main__':
    app.run(debug=True)
