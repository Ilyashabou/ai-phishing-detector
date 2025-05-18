import joblib
import pandas as pd

# Load the model
model_path = 'models/phishing_model.pkl'
try:
    model = joblib.load(model_path)
    
    # Print model information
    print("Model type:", type(model).__name__)
    
    # Check if model has feature_names_in_ attribute (scikit-learn 1.0+)
    if hasattr(model, 'feature_names_in_'):
        print("\nExpected features:")
        for feature in model.feature_names_in_:
            print(f"- {feature}")
    else:
        print("\nModel doesn't have feature_names_in_ attribute")
        
    # Try to extract feature names from model attributes
    print("\nAttempting to find feature names through other attributes:")
    for attr in dir(model):
        if 'feature' in attr.lower() or 'coef' in attr.lower():
            try:
                value = getattr(model, attr)
                if isinstance(value, (list, pd.Series, pd.DataFrame)) or hasattr(value, 'shape'):
                    print(f"- {attr}: {value}")
            except:
                pass
                
    # If it's a pipeline, check each step
    if hasattr(model, 'steps'):
        print("\nPipeline steps:")
        for name, step in model.steps:
            print(f"- {name}: {type(step).__name__}")
            
            if hasattr(step, 'feature_names_in_'):
                print(f"  Features for {name}:")
                for feature in step.feature_names_in_:
                    print(f"  - {feature}")
    
except Exception as e:
    print(f"Error loading model: {str(e)}") 