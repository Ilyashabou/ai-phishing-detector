import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import os

def load_model(model_path):
    try:
        model = joblib.load(model_path)
        return model
    except FileNotFoundError:
        print(f"Model file not found at {model_path}.")
        return None
    except Exception as e:
        print(f"An error occurred while loading the model: {e}")
        return None

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

def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"Evaluation Metrics:\n"
          f"Accuracy: {accuracy:.4f}\n"
          f"Precision: {precision:.4f}\n"
          f"Recall: {recall:.4f}\n"
          f"F1-score: {f1:.4f}\n")
    
    return y_pred

def plot_confusion_matrix(y_test, y_pred):
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Legitimate', 'Phishing'], yticklabels=['Legitimate', 'Phishing'])
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.title('Confusion Matrix')
    plt.show()

def main():
    # Load the model
    model = load_model('models/phishing_model.pkl')
    if model is None:
        return

    # Load the test dataset
    test_df = load_data('data/processed/test.csv')

    # Extract features and target
    feature_columns = ['url_length', 'num_dots', 'has_https', 'num_hyphens', 'num_subdirs', 'has_ip', 'suspicious_word']
    X_test = test_df[feature_columns]
    y_test = test_df['label']

    # Evaluate the model
    y_pred = evaluate_model(model, X_test, y_test)

    # Plot confusion matrix
    plot_confusion_matrix(y_test, y_pred)

if __name__ == "__main__":
    main()
