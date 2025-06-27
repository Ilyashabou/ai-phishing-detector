# AI Phishing URL Detector

An advanced machine learning system for detecting phishing URLs with high accuracy and low false positives. This project includes a trained model, a web application, and a browser extension for real-time phishing detection.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [Web Application](#web-application)
  - [Browser Extension](#browser-extension)
  - [API](#api)
  - [Command Line](#command-line)
- [Technical Details](#technical-details)
  - [Feature Extraction](#feature-extraction)
  - [Model Training](#model-training)
  - [Evaluation](#evaluation)
- [Future Improvements](#future-improvements)

## Overview

The AI Phishing URL Detector is a comprehensive solution for identifying potentially malicious phishing websites. It uses machine learning to analyze various aspects of URLs and determine whether they are legitimate or phishing attempts. The system provides detailed explanations of its decisions, making it both powerful and transparent.

The project consists of several components:
1. A core machine learning model trained on phishing and legitimate URLs
2. A feature extraction system that analyzes URL characteristics
3. A Flask web application for manual URL checking
4. A FastAPI backend for programmatic access
5. A browser extension for real-time protection

## Features

This phishing detection system analyzes URLs using the following feature categories:

### Security Indicators
- **HTTPS Usage**: Checks if the URL uses secure HTTPS protocol
- **IP Address**: Detects IP addresses used in URLs (common in phishing)
- **Special Characters**: Identifies unusual special characters in URLs
- **Suspicious TLDs**: Flags top-level domains commonly used in phishing

### Content Indicators
- **Suspicious Words**: Detects common words used in phishing URLs
- **Login Keywords**: Identifies login-related terms that may indicate phishing

### Reputation Indicators
- **Domain in Top 1M**: Checks if the domain is among the top 1 million websites
- **WHOIS Domain Age**: Analyzes how long the domain has existed

### Structural Indicators
- **URL Length**: Measures total URL length
- **Domain Length**: Measures domain name length
- **Dots Count**: Counts dots in the URL
- **Hyphens Count**: Counts hyphens in the domain
- **Subdirectories Count**: Analyzes URL path structure
- **Digits Count**: Counts numeric characters in the URL

## Project Structure

```
ai-phishing-detector/
├── app/                      # Web application and API
│   ├── api.py                # FastAPI implementation
│   ├── app.py                # Flask web application
│   ├── templates/            # HTML templates
│   │   └── index.html        # Main web interface
│   └── README.md             # Web app documentation
├── data/                     # Data files
│   ├── processed/            # Processed datasets
│   │   ├── test.csv          # Test dataset
│   │   └── train.csv         # Training dataset
│   └── raw/                  # Raw data sources
│       ├── top-1m.csv        # Top 1 million domains list
│       └── verified_online.csv # Verified phishing URLs
├── extension/                # Browser extension
│   ├── background.js         # Background script
│   ├── blocked.html          # Phishing warning page
│   ├── blocked.js            # Warning page functionality
│   ├── content.js            # Content script
│   ├── icons/                # Extension icons
│   ├── manifest.json         # Extension configuration
│   ├── popup.html            # Extension popup UI
│   └── popup.js              # Popup functionality
├── models/                   # Trained models
│   ├── phishing_model.pkl    # Main phishing detection model
│   └── feature_names.pkl     # Feature names used by model
├── notebooks/                # Jupyter notebooks
│   └── EDA.ipynb             # Exploratory data analysis
├── src/                      # Source code
│   ├── evaluate.py           # Model evaluation
│   ├── predict.py            # Prediction functionality
│   ├── retrain_model.py      # Model retraining
│   ├── train.py              # Model training
│   └── url_feature_extractor.py # URL feature extraction
├── tests/                    # Test scripts
│   ├── check_model.py        # Model verification
│   ├── test_model.py         # Model testing
│   └── test_predict.py       # Prediction testing
├── requirements.txt          # Python dependencies
└── README.md                 # Main documentation
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/ai-phishing-detector.git
   cd ai-phishing-detector
   ```

2. Install requirements:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Download the top 1 million domains list:
   ```
   mkdir -p data/raw
   # Download top-1m.csv and place it in data/raw/
   ```

## Usage

### Web Application

1. Start the Flask web application:
   ```
   cd app
   python app.py
   ```

2. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

3. Enter a URL in the input field and click "Analyze" to check if it's a phishing site.

### Browser Extension

1. Start the FastAPI backend:
   ```
   cd app
   uvicorn api:app --host 0.0.0.0 --port 8000
   ```

2. Load the extension in your browser:
   - Chrome/Edge: Go to `chrome://extensions/`, enable "Developer mode", click "Load unpacked", and select the `extension` folder.
   - Firefox: Go to `about:debugging#/runtime/this-firefox`, click "Load Temporary Add-on", and select any file in the `extension` folder.

3. The extension will now check URLs as you browse and warn you about potential phishing sites.

### API

The FastAPI backend provides a simple API for phishing detection:

```
GET http://localhost:8000/predict?url=https://example.com
```

Response format:
```json
{
  "url": "https://example.com",
  "result": "Legitimate",
  "is_phishing": false,
  "confidence": 0.95,
  "features": {
    "Security Indicators": { ... },
    "Content Indicators": { ... },
    "Reputation Indicators": { ... },
    "Structural Indicators": { ... }
  }
}
```

### Command Line

You can also use the command-line interface for quick URL checks:

```
python src/predict.py
```

This will prompt you to enter URLs for analysis and display the results in the terminal.

## Technical Details

### Feature Extraction

The system extracts various features from URLs using the `url_feature_extractor.py` module. These features include:

- URL structure analysis (length, dots, hyphens, etc.)
- Domain reputation checks (age, presence in top domains)
- Content analysis (suspicious words, login keywords)
- Security indicators (HTTPS, IP addresses, suspicious TLDs)

The feature extraction process is designed to be robust, handling various edge cases and timeouts for external services like WHOIS lookups.

### Model Training

The model is trained using a balanced dataset of legitimate and phishing URLs. The training process:

1. Loads and preprocesses the data
2. Balances the dataset to prevent bias
3. Trains multiple models (Logistic Regression, Random Forest, Calibrated Random Forest)
4. Selects the best model based on F1-score
5. Saves the model and feature names for later use

The default model is a Calibrated Random Forest classifier, which provides well-calibrated probability estimates for confidence scoring.

### Evaluation

The model is evaluated using standard metrics:

- Accuracy: Overall correctness
- Precision: Ability to avoid false positives
- Recall: Ability to detect all phishing sites
- F1-score: Harmonic mean of precision and recall

The evaluation process includes confusion matrix analysis and detailed classification reports.

## Future Improvements

- Enhanced feature extraction with NLP techniques
- Integration with URL reputation databases
- Continuous learning from user feedback
- Support for more languages and international domains
- Mobile application development
- Improved performance for very long URLs
- Integration with email clients for phishing email detection
