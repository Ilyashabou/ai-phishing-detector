import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.utils import resample
import joblib
import os

def load_data(file_path):
    try:
        df = pd.read_csv(file_path)
        if df.empty:
            raise ValueError(f"The dataset at {file_path} is empty.")
        return df
    except FileNotFoundError:
        raise FileNotFoundError(f"The dataset at {file_path} was not found.")
    except Exception as e:
        raise Exception(f"An error occurred while loading the dataset: {e}")

# Load datasets
train_df = load_data('data/processed/train.csv')
test_df = load_data('data/processed/test.csv')

# Print class distribution to check for imbalance
print("\nBefore balancing:", train_df['label'].value_counts())
try:
    imbalance_ratio = train_df['label'].value_counts()[1]/train_df['label'].value_counts()[0]
    print(f"Class distribution ratio: {imbalance_ratio:.4f}\n")
except:
    print("Unable to calculate class distribution ratio - check if both classes exist\n")

# Balance the dataset by downsampling
# Separate majority and minority classes
phishing_df = train_df[train_df['label'] == 1]
legitimate_df = train_df[train_df['label'] == 0]

# Downsample the majority class to match minority
min_size = min(len(phishing_df), len(legitimate_df))
phishing_downsampled = resample(phishing_df, replace=False, n_samples=min_size, random_state=42)
legitimate_downsampled = resample(legitimate_df, replace=False, n_samples=min_size, random_state=42)

# Combine balanced data
balanced_df = pd.concat([phishing_downsampled, legitimate_downsampled])
print("After balancing:", balanced_df['label'].value_counts())
print(f"New class distribution ratio: {balanced_df['label'].value_counts()[1]/balanced_df['label'].value_counts()[0]:.4f}\n")

# Identify all feature columns dynamically (excluding label and url)
feature_columns = [col for col in balanced_df.columns if col not in ['label', 'url']]
print(f"Detected {len(feature_columns)} features:")
print(feature_columns)

# Separate features and target from balanced dataset
X_train = balanced_df[feature_columns]
y_train = balanced_df['label']
X_test = test_df[feature_columns]
y_test = test_df['label']

# Print and save the feature names used in training
print("\nFeatures used in training:")
print(feature_columns)
model_feature_names = feature_columns

# Define models with class weighting to handle imbalance
base_rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=10,
    class_weight='balanced',
    random_state=42
)

# Use CalibratedClassifierCV to get better probability estimates
models = {
    'Logistic Regression': LogisticRegression(max_iter=1000, class_weight='balanced'),
    'Random Forest': base_rf,
    'Calibrated Random Forest': CalibratedClassifierCV(base_rf, cv=5, method='sigmoid')
}

# Train and evaluate models
best_model = None
best_score = 0

for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"{name} - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1-score: {f1:.4f}")
    
    # Print confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:\n{cm}\n")
    
    # Print classification report for better insight
    print(f"Classification Report for {name}:\n", classification_report(y_test, y_pred))
    
    if f1 > best_score:
        best_score = f1
        best_model = model

# Save the best model
os.makedirs('models', exist_ok=True)
model_filename = 'models/phishing_model.pkl'
feature_names_filename = 'models/feature_names.pkl'

joblib.dump(best_model, model_filename)
joblib.dump(model_feature_names, feature_names_filename)  # Save feature names

print(f"🏆 Best Model: {type(best_model).__name__} with F1-score: {best_score:.4f}")
print(f"Model saved to: {model_filename}")
print(f"Feature names saved to: {feature_names_filename}")
