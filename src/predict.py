import joblib
import pandas as pd
import os
from url_feature_extractor import extract_features

def load_model(model_path, feature_names_path):
    """Load the trained model and feature names with error handling"""
    try:
        model = joblib.load(model_path)
        feature_names = joblib.load(feature_names_path)
        return model, feature_names
    except FileNotFoundError:
        print(f"❌ Error: Model or feature names file not found")
        print("Please make sure you've trained the model first using train.py")
        return None, None
    except Exception as e:
        print(f"❌ Error loading model or feature names: {str(e)}")
        return None, None

def validate_url(url):
    """Validate URL format"""
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    url = url.strip()
    if not url:
        return False, "URL cannot be empty"
    
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with 'http://' or 'https://'"
    
    return True, url

def format_feature_value(feature, value):
    """Format feature values for better readability"""
    if feature == 'whois_days_old':
        if value == 0:
            return "Unknown"
        elif value < 30:
            return f"{value} days (Very New ⚠️)"
        elif value < 180:
            return f"{value} days (New)"
        else:
            return f"{value} days (Established ✓)"
    
    elif feature in ['domain_in_top1m', 'has_https', 'has_ip', 'has_login_keyword', 
                    'suspicious_word', 'tld_suspicious', 'has_special_chars']:
        if feature == 'domain_in_top1m' and value == 1:
            return "Yes ✓"
        elif feature == 'has_https' and value == 1:
            return "Yes ✓"
        elif feature == 'has_ip' and value == 1:
            return "Yes ⚠️"
        elif feature == 'has_login_keyword' and value == 1:
            return "Yes ⚠️"
        elif feature == 'suspicious_word' and value == 1:
            return "Yes ⚠️"
        elif feature == 'tld_suspicious' and value == 1:
            return "Yes ⚠️"
        elif feature == 'has_special_chars' and value == 1:
            return "Yes ⚠️"
        else:
            return "No"
    
    # Default formatting for other features
    return value

def main():
    # Load the model and feature names
    model_path = 'models/phishing_model.pkl'
    feature_names_path = 'models/feature_names.pkl'
    model, model_feature_names = load_model(model_path, feature_names_path)
    if model is None or model_feature_names is None:
        return

    print("\n🔍 Phishing URL Detector")
    print("=" * 30)
    
    while True:
        url = input("\nEnter URL to check (or 'q' to quit): ").strip()
        
        if url.lower() == 'q':
            break
            
        # Validate URL
        is_valid, message = validate_url(url)
        if not is_valid:
            print(f"⚠️  {message}")
            continue
            
        try:
            print("\nAnalyzing URL...")
            print(f"🔗 URL: {url}")
            
            # Extract features
            features = extract_features(url)
            
            # Ensure features match what was used in training
            # First, identify which features are available
            available_features = set(features.index)
            model_features_set = set(model_feature_names)
            
            # Report if new features aren't being used by the model
            unused_features = available_features - model_features_set
            if unused_features:
                print(f"\n⚠️ Some features not used by model: {', '.join(unused_features)}")
            
            # Report if model expects features that aren't available
            missing_features = model_features_set - available_features
            if missing_features:
                print(f"\n⚠️ Some model features unavailable: {', '.join(missing_features)}")
            
            # Ensure features match what was used in training
            features = features.reindex(model_feature_names, fill_value=0)
            features_df = pd.DataFrame([features])
            
            # Make prediction
            prediction = model.predict(features_df)[0]
            result = "Phishing" if prediction == 1 else "Legitimate"
            
            # Get confidence score if available
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(features_df)[0][1]  # Probability of class 1 (Phishing)
                if result == "Phishing":
                    print(f"🔴 Prediction: {result} (Confidence: {proba:.2%})")
                else:
                    print(f"🟢 Prediction: {result} (Confidence: {1-proba:.2%})")
            else:
                if result == "Phishing":
                    print(f"🔴 Prediction: {result}")
                else:
                    print(f"🟢 Prediction: {result}")
            
            # Print feature details
            print("\n📊 URL Features:")
            
            # Group features by category
            security_features = ['has_https', 'has_ip', 'has_special_chars', 'tld_suspicious']
            content_features = ['suspicious_word', 'has_login_keyword']
            reputation_features = ['domain_in_top1m', 'whois_days_old']
            structural_features = ['url_length', 'domain_length', 'num_dots', 'num_hyphens', 
                                  'num_subdirs', 'num_digits']
            
            # Print security features
            print("\n  🔒 Security Indicators:")
            for feature in security_features:
                if feature in features:
                    print(f"    • {feature.replace('_', ' ').title()}: {format_feature_value(feature, features[feature])}")
            
            # Print content features
            print("\n  📝 Content Indicators:")
            for feature in content_features:
                if feature in features:
                    print(f"    • {feature.replace('_', ' ').title()}: {format_feature_value(feature, features[feature])}")
            
            # Print reputation features
            print("\n  🌐 Reputation Indicators:")
            for feature in reputation_features:
                if feature in features:
                    print(f"    • {feature.replace('_', ' ').title()}: {format_feature_value(feature, features[feature])}")
            
            # Print structural features
            print("\n  🏗️ Structural Indicators:")
            for feature in structural_features:
                if feature in features:
                    print(f"    • {feature.replace('_', ' ').title()}: {features[feature]}")
            
        except Exception as e:
            print(f"❌ Error analyzing URL: {str(e)}")
            import traceback
            traceback.print_exc()
            
    print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()