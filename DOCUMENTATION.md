# AI Phishing URL Detector - Complete Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Project Structure](#project-structure)
3. [Features and Indicators](#features-and-indicators)
4. [Installation](#installation)
5. [Usage](#usage)
   - [Command Line Interface](#command-line-interface)
   - [Web Application](#web-application)
   - [Docker Deployment](#docker-deployment)
6. [Technical Implementation](#technical-implementation)
   - [Feature Extraction](#feature-extraction)
   - [Model Training](#model-training)
   - [Prediction System](#prediction-system)
   - [Evaluation Metrics](#evaluation-metrics)
7. [Dataset Information](#dataset-information)
8. [Future Improvements](#future-improvements)
9. [Troubleshooting](#troubleshooting)
10. [API Reference](#api-reference)
11. [Contributing](#contributing)
12. [License](#license)

## Project Overview

The AI Phishing URL Detector is a sophisticated machine learning system designed to identify phishing URLs with high accuracy and low false positives. This project leverages a comprehensive set of features extracted from URLs and employs a calibrated Random Forest classifier to make reliable predictions about whether a URL is legitimate or potentially malicious.

The system is designed to be:
- **Accurate**: Achieves high precision and recall in phishing detection
- **Balanced**: Handles both phishing and legitimate URLs effectively
- **Explainable**: Provides detailed feature analysis for each prediction
- **Deployable**: Can be used as a command-line tool, web application, or containerized service

## Project Structure

```
ai-phishing-detector/
├── .dockerignore          # Files to exclude from Docker build
├── .gitattributes         # Git LFS configuration for large files
├── .gitignore             # Git ignore configuration
├── Dockerfile             # Docker container configuration
├── LICENSE                # Project license
├── README.md              # Project overview
├── app/                   # Web application
│   ├── README.md          # Web app documentation
│   ├── app.py             # Flask web application
│   └── templates/         # HTML templates
│       └── index.html     # Main web interface
├── data/                  # Data directory
│   ├── processed/         # Processed datasets
│   │   ├── test.csv       # Test dataset
│   │   └── train.csv      # Training dataset
│   └── raw/               # Raw datasets
│       ├── top-1m.csv     # Top 1 million legitimate domains
│       └── verified_online.csv # Verified phishing URLs
├── models/                # Trained models
│   ├── RandomForestClassifier_phishing_model.pkl # Main model
│   ├── feature_names.pkl  # Feature names used by the model
│   └── phishing_model.pkl # Alternative model
├── notebooks/             # Jupyter notebooks
│   └── EDA.ipynb          # Exploratory Data Analysis
├── requirements.txt       # Python dependencies
├── src/                   # Source code
│   ├── __init__.py        # Package initialization
│   ├── evaluate.py        # Model evaluation
│   ├── predict.py         # URL prediction
│   ├── retrain_model.py   # Model retraining
│   ├── train.py           # Model training
│   └── url_feature_extractor.py # Feature extraction
└── tests/                 # Test suite
    ├── check_model.py     # Model verification
    ├── test_model.py      # Model tests
    └── test_predict.py    # Prediction tests
```

## Features and Indicators

The system extracts and analyzes the following features from URLs:

### Security Indicators
- **HTTPS Usage**: Checks if the URL uses secure HTTPS protocol, which is more common in legitimate websites.
- **IP Address**: Detects if IP addresses are used in URLs instead of domain names, which is a common phishing technique.
- **Special Characters**: Identifies unusual special characters in URLs that may be used to obfuscate malicious intent.
- **Suspicious TLDs**: Flags top-level domains that are commonly associated with phishing attempts.

### Content Indicators
- **Suspicious Words**: Detects common words and phrases frequently used in phishing URLs (e.g., "secure", "account", "verify").
- **Login Keywords**: Identifies login-related terms that may indicate phishing attempts targeting user credentials.

### Reputation Indicators
- **Domain in Top 1M**: Checks if the domain is among the top 1 million most visited websites, which are typically legitimate.
- **WHOIS Domain Age**: Analyzes how long the domain has existed. Newer domains are more likely to be used for phishing.

### Structural Indicators
- **URL Length**: Measures the total URL length. Phishing URLs tend to be longer to hide their true nature.
- **Domain Length**: Measures the domain name length. Excessively long domains may indicate phishing.
- **Dots Count**: Counts the number of dots in the URL. More dots can indicate subdomain abuse.
- **Hyphens Count**: Counts hyphens in the domain. Excessive hyphens are more common in phishing domains.
- **Subdirectories Count**: Analyzes the URL path structure. Complex paths can be used to obscure phishing content.
- **Digits Count**: Counts numeric characters in the URL. Higher digit counts can be suspicious.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git (optional, for cloning the repository)

### Standard Installation

1. Clone the repository (or download it directly):
   ```
   git clone https://github.com/Ilyashabou/ai-phishing-detector.git
   cd ai-phishing-detector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Docker Installation

If you prefer to use Docker:

1. Make sure Docker is installed on your system.
2. Build the Docker image:
   ```
   docker build -t phishing-detector .
   ```

## Usage

### Command Line Interface

The project provides a command-line interface for URL analysis:

#### Analyzing URLs

```
python src/predict.py
```

This will prompt you to enter a URL for analysis. The system will:
- Extract features from the URL
- Apply the trained model to make a prediction
- Display the result (phishing or legitimate) with a confidence score
- Show a detailed breakdown of the features that influenced the decision

#### Training the Model

If you want to retrain the model with your own data:

```
python src/train.py
```

This will:
- Load and preprocess the datasets from the data directory
- Balance the data to prevent bias toward either class
- Train multiple models and select the best performing one
- Save the model and feature names to the models directory

#### Evaluating the Model

To evaluate the model's performance:

```
python src/evaluate.py
```

This will generate performance metrics including:
- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix
- ROC Curve

### Web Application

The project includes a Flask web application for easy interaction:

1. Start the web server:
   ```
   python app/app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Enter a URL in the input field and click "Check URL"

4. View the analysis results, including:
   - Overall verdict (phishing or legitimate)
   - Confidence score
   - Feature breakdown with visual indicators

### Docker Deployment

If you've built the Docker image:

1. Run the container:
   ```
   docker run -p 5000:5000 phishing-detector
   ```

2. Access the web interface at:
   ```
   http://localhost:5000
   ```

## Technical Implementation

### Feature Extraction

The feature extraction process is implemented in `src/url_feature_extractor.py` and follows these steps:

1. **URL Normalization**: Standardizes URLs by converting to lowercase, removing protocols, and handling edge cases.
2. **Domain Extraction**: Extracts the domain from the URL using URL parsing techniques.
3. **Feature Calculation**: Computes various features based on URL structure, content, and reputation.
4. **Feature Vectorization**: Converts the extracted features into a format suitable for machine learning models.

The system includes robust error handling to deal with malformed URLs, network issues during WHOIS lookups, and other potential problems.

### Model Training

The model training process is implemented in `src/train.py` and includes:

1. **Data Loading**: Loads datasets from CSV files with appropriate error handling.
2. **Data Balancing**: Ensures equal representation of phishing and legitimate URLs to prevent bias.
3. **Feature Selection**: Dynamically identifies and uses all available features.
4. **Model Selection**: Trains and evaluates multiple classifier types:
   - Random Forest Classifier
   - Logistic Regression
   - Calibrated versions of both
5. **Hyperparameter Tuning**: Uses grid search to find optimal model parameters.
6. **Model Persistence**: Saves the trained model and feature names for later use.

### Prediction System

The prediction system is implemented in `src/predict.py` and provides:

1. **Interactive Interface**: Allows users to input URLs for analysis.
2. **Feature Extraction**: Extracts features from the provided URL.
3. **Prediction**: Applies the trained model to make a prediction.
4. **Confidence Scoring**: Provides a calibrated confidence score for the prediction.
5. **Feature Importance**: Highlights which features contributed most to the decision.
6. **Formatted Output**: Presents results in a user-friendly format with visual indicators.

### Evaluation Metrics

The model evaluation is implemented in `src/evaluate.py` and calculates:

1. **Accuracy**: Overall correctness of predictions.
2. **Precision**: Proportion of true positives among positive predictions.
3. **Recall**: Proportion of true positives identified correctly.
4. **F1 Score**: Harmonic mean of precision and recall.
5. **Confusion Matrix**: Breakdown of true/false positives/negatives.
6. **ROC Curve**: Visualization of the true positive rate vs. false positive rate.

## Dataset Information

The model is trained on a combination of datasets:

1. **Verified Phishing URLs**: A collection of URLs confirmed to be used in phishing attacks.
   - Source: `data/raw/verified_online.csv`
   - Contains URLs from phishing databases and security reports

2. **Top 1 Million Legitimate Websites**: A list of the most visited legitimate websites.
   - Source: `data/raw/top-1m.csv`
   - Based on traffic rankings from services like Alexa or Tranco

3. **Processed Datasets**: The raw data is processed and split into training and testing sets.
   - `data/processed/train.csv`: Used for model training
   - `data/processed/test.csv`: Used for model evaluation

## Future Improvements

Potential enhancements for the project include:

1. **Real-time URL Scanning API**: Develop a RESTful API for integration with other services.
2. **Browser Extension Integration**: Create browser extensions that can check URLs in real-time.
3. **Additional Features**:
   - HTML content analysis
   - JavaScript behavior analysis
   - Screenshot-based visual similarity detection
   - Certificate analysis for HTTPS sites
4. **Feedback-based Learning**: Implement a system to collect user feedback for continuous model improvement.
5. **Multi-model Ensemble**: Combine multiple models for improved accuracy.
6. **Internationalization**: Enhance detection for non-English phishing attempts.
7. **Mobile App**: Develop a mobile application for URL checking on smartphones.

## Troubleshooting

### Common Issues and Solutions

1. **Missing Dependencies**:
   - Error: `ModuleNotFoundError: No module named 'X'`
   - Solution: Ensure all dependencies are installed with `pip install -r requirements.txt`

2. **Model Not Found**:
   - Error: `FileNotFoundError: [Errno 2] No such file or directory: 'models/phishing_model.pkl'`
   - Solution: Run `python src/train.py` to generate the model files

3. **WHOIS Lookup Failures**:
   - Error: `Error in WHOIS lookup for domain X`
   - Solution: The system will continue with a default value. Consider using a VPN if you're experiencing rate limiting.

4. **Large File Handling with Git**:
   - Issue: Problems pushing large model files to Git
   - Solution: The project uses Git LFS for large files. Ensure Git LFS is installed and initialized.

## API Reference

### URL Feature Extractor

```python
from src.url_feature_extractor import extract_features

# Extract features from a URL
features = extract_features("https://example.com")
```

### Prediction Module

```python
from src.predict import load_model, predict_url

# Load the model
model, feature_names = load_model("models/phishing_model.pkl", "models/feature_names.pkl")

# Make a prediction
result, confidence, feature_values = predict_url(model, feature_names, "https://example.com")
```

### Web Application

The Flask application provides a simple API endpoint:

```
POST /api/check
Content-Type: application/json

{
    "url": "https://example.com"
}
```

Response:
```json
{
    "url": "https://example.com",
    "is_phishing": false,
    "confidence": 0.95,
    "features": {
        "url_length": 22,
        "has_https": 1,
        ...
    }
}
```

## Contributing

Contributions to the project are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the project's style guidelines and includes appropriate tests.

## License

This project is licensed under the terms included in the LICENSE file.

---

*Documentation created: May 18, 2025*
