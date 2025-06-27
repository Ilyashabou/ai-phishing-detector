import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from src.url_feature_extractor import extract_features
import os

print("Creating a new model with advanced phishing detection features...")

# Create synthetic training data
def create_synthetic_data(num_samples=1000):
    print(f"Generating {num_samples} synthetic samples for training...")
    
    # Generate legitimate URLs
    legitimate_domains = [
        'github.com', 'google.com', 'youtube.com', 'facebook.com', 
        'twitter.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'linkedin.com', 'netflix.com', 'wikipedia.org', 'yahoo.com'
    ]
    
    legitimate_urls = []
    for domain in legitimate_domains:
        # Generate variations of legitimate URLs
        legitimate_urls.append(f"https://{domain}")
        legitimate_urls.append(f"https://www.{domain}")
        legitimate_urls.append(f"https://{domain}/login")
        legitimate_urls.append(f"https://{domain}/account")
        legitimate_urls.append(f"https://{domain}/products")
        legitimate_urls.append(f"https://{domain}/search?q=test")
        legitimate_urls.append(f"https://{domain}/watch?v=12345")  # YouTube style
        legitimate_urls.append(f"https://{domain}/search?q=test&lang=en")  # Search params
    
    # Generate phishing URLs
    phishing_patterns = [
        "login-secure-{}.com",
        "verify-{}-account.com",
        "{}-login.tk",
        "secure-{}.ml",
        "{}-verification.ga",
        "account-{}.cf",
        "signin-{}.xyz",
        "{}-authenticate.top",
        "security-{}.gq",
        "{}-update.cc"
    ]
    
    # Add more deceptive phishing patterns
    phishing_patterns.extend([
        "{}-support-team.com",
        "{}signin.com",
        "{}.secure-login.com",
        "signin-{}-verify.com",
        "{}-accounts-verify.com",
        "security-{}-system.com"
    ])
    
    phishing_urls = []
    for domain in legitimate_domains:
        domain_base = domain.split('.')[0]  # Get base name like 'github' from 'github.com'
        for pattern in phishing_patterns:
            phishing_url = f"https://{pattern.format(domain_base)}"
            phishing_urls.append(phishing_url)
    
    # Create dataframe with balanced classes
    num_legitimate = min(len(legitimate_urls), num_samples // 2)
    num_phishing = min(len(phishing_urls), num_samples // 2)
    
    legitimate_samples = np.random.choice(legitimate_urls, num_legitimate, replace=False)
    phishing_samples = np.random.choice(phishing_urls, num_phishing, replace=False)
    
    urls = np.concatenate([legitimate_samples, phishing_samples])
    labels = np.concatenate([np.zeros(num_legitimate), np.ones(num_phishing)])
    
    # Shuffle the data
    idx = np.random.permutation(len(urls))
    urls, labels = urls[idx], labels[idx]
    
    return urls, labels

# Generate synthetic data
urls, labels = create_synthetic_data(2000)

# Extract features
print("Extracting features from URLs...")
feature_list = []
for url in urls:
    try:
        features = extract_features(url)
        feature_list.append(features)
    except Exception as e:
        print(f"Error extracting features for {url}: {e}")
        # Add empty features
        feature_list.append(pd.Series())

# Convert to DataFrame
features_df = pd.DataFrame(feature_list)

# Handle missing values
features_df = features_df.fillna(0)

# Add the phishing signals before dropping columns
features_df['phishing_signals'] = (
    features_df['has_ip'] * 3 + 
    features_df['tld_suspicious'] * 2 + 
    features_df['has_special_chars'] + 
    features_df['has_login_keyword'] - 
    features_df['domain_in_top1m'] * 5
)

# Mark legitimate domains
features_df.loc[features_df['domain_in_top1m'] == 1, 'is_legitimate'] = 1

# Drop any columns you don't want in the model
features_df_clean = features_df.drop(['is_legitimate'], axis=1, errors='ignore')

# Then split the clean data
X_train, X_test, y_train, y_test = train_test_split(
    features_df_clean, labels, test_size=0.2, random_state=42, stratify=labels
)

# Now train with the properly split data
print(f"Training with {X_train.shape[1]} features: {list(X_train.columns)}")

# Train Random Forest
print("Training Random Forest classifier...")
rf = RandomForestClassifier(
    n_estimators=200,  # More trees
    max_depth=25,      # Deeper trees
    class_weight='balanced_subsample',  # Better for imbalanced data
    random_state=42
)
rf.fit(X_train, y_train)

# Apply calibration for better probability estimates
print("Calibrating model probabilities...")
calibrated_rf = CalibratedClassifierCV(rf, method='sigmoid', cv=5)
calibrated_rf.fit(X_train, y_train)

# Evaluate
y_pred = calibrated_rf.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model and feature names
print("Saving model and feature names...")
os.makedirs('models', exist_ok=True)

model_filename = 'models/phishing_model.pkl'
feature_names_filename = 'models/feature_names.pkl'
feature_names = list(X_train.columns)

joblib.dump(calibrated_rf, model_filename)
joblib.dump(feature_names, feature_names_filename)

print(f"\n✅ Model saved to: {model_filename}")
print(f"✅ Feature names saved to: {feature_names_filename}")
print(f"✅ Features used: {feature_names}")

print("\nYou can now run src/predict.py to test with real URLs.") 