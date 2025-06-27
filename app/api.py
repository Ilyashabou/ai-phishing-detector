import sys
import os
# Add the parent directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import numpy as np
from src.url_feature_extractor import extract_features

# Helper function to convert numpy types to Python native types
def convert_numpy_types(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj

app = FastAPI()

# Enable CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Define the parent directory path
PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Load trained model and feature names
try:
    model = joblib.load(os.path.join(PARENT_DIR, 'models/phishing_model.pkl'))
    feature_names = joblib.load(os.path.join(PARENT_DIR, 'models/feature_names.pkl'))
    print(f"Model loaded successfully from {os.path.join(PARENT_DIR, 'models/phishing_model.pkl')}")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    model = None
    feature_names = None

@app.get("/")
def read_root():
    return {"message": "AI Phishing Detector API"}

@app.get("/predict")
def predict(url: str = Query(...)):
    if model is None:
        return {"error": "Model not loaded"}
        
    try:
        # Extract features
        features = extract_features(url)
        
        # Ensure features match what was used in training
        if feature_names:
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
        
        # Format features for explanation
        formatted_features = {}
        
        # Group features by category
        security_features = ['has_https', 'has_ip', 'has_special_chars', 'tld_suspicious']
        content_features = ['suspicious_word', 'has_login_keyword']
        reputation_features = ['domain_in_top1m', 'whois_days_old']
        structural_features = ['url_length', 'domain_length', 'num_dots', 'num_hyphens', 'num_subdirs', 'num_digits']
        
        # Format feature values
        for feature in features.index:
            # Convert numpy value to Python native type
            value = convert_numpy_types(features[feature])
            
            if feature == 'whois_days_old':
                if value == 0:
                    formatted_value = "Unknown"
                elif value < 30:
                    formatted_value = f"{value} days (Very New ⚠️)"
                elif value < 180:
                    formatted_value = f"{value} days (New)"
                else:
                    formatted_value = f"{value} days (Established ✓)"
            elif feature in ['domain_in_top1m', 'has_https']:
                formatted_value = "Yes ✓" if value == 1 else "No"
            elif feature in ['has_ip', 'has_login_keyword', 'suspicious_word', 'tld_suspicious', 'has_special_chars']:
                formatted_value = "Yes ⚠️" if value == 1 else "No"
            else:
                formatted_value = value
                
            # Determine category
            if feature in security_features:
                category = "Security Indicators"
            elif feature in content_features:
                category = "Content Indicators"
            elif feature in reputation_features:
                category = "Reputation Indicators"
            elif feature in structural_features:
                category = "Structural Indicators"
            else:
                category = "Other Indicators"
                
            # Add to formatted features
            if category not in formatted_features:
                formatted_features[category] = {}
                
            formatted_features[category][feature.replace('_', ' ').title()] = formatted_value
        
        # Create response dictionary with all values converted to Python native types
        response = {
            "url": url,
            "result": result,
            "is_phishing": bool(prediction),
            "confidence": confidence,
            "features": formatted_features
        }
        
        # Ensure all values are JSON serializable
        response = convert_numpy_types(response)
        
        return response
        
    except Exception as e:
        return {"error": str(e)}