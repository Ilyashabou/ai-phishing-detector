# AI Phishing URL Detector

An advanced machine learning model for detecting phishing URLs with high accuracy and low false positives.

## Features

This phishing detection system uses the following features:

### Security Indicators
- HTTPS Usage: Checks if the URL uses secure HTTPS protocol
- IP Address: Detects IP addresses used in URLs (common in phishing)
- Special Characters: Identifies unusual special characters in URLs
- Suspicious TLDs: Flags top-level domains commonly used in phishing

### Content Indicators
- Suspicious Words: Detects common words used in phishing URLs
- Login Keywords: Identifies login-related terms that may indicate phishing

### Reputation Indicators
- Domain in Top 1M: Checks if the domain is among the top 1 million websites
- WHOIS Domain Age: Analyzes how long the domain has existed

### Structural Indicators
- URL Length: Measures total URL length
- Domain Length: Measures domain name length
- Dots Count: Counts dots in the URL
- Hyphens Count: Counts hyphens in the domain
- Subdirectories Count: Analyzes URL path structure
- Digits Count: Counts numeric characters in the URL

## Model

The system uses a Calibrated Random Forest classifier, which provides:
- High accuracy in phishing detection
- Balanced handling of phishing and legitimate URLs
- Well-calibrated confidence scores

## Installation

1. Clone this repository
2. Install requirements:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Training the model

```
python src/train.py
```

This will:
- Load and preprocess the datasets
- Balance the data to prevent bias
- Train multiple models and select the best one
- Save the model and feature names

### Making predictions

```
python src/predict.py
```

This allows you to:
- Enter URLs to check
- Get phishing/legitimate predictions with confidence scores
- See detailed feature analysis for each URL

## Dataset

The model is trained on:
- Verified phishing URLs
- Top 1 million legitimate websites
- Curated URL datasets with known labels

## Future Improvements

- Real-time URL scanning API
- Browser extension integration
- Additional behavioral features
- Feedback-based continuous learning
