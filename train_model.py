import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

def train_phishguard_model():
    print("Loading training matrix...")
    try:
        df = pd.read_csv('data/processed/training_matrix.csv')
    except FileNotFoundError:
        print("Error: training_matrix.csv not found.")
        return
    
    print(f"Dataset Loaded. Total rows: {len(df)}")
    X = df.drop(columns = ['label', 'domain_age_days'], errors = 'ignore')
    y = df['label']
    print("Split data into training and testing sets")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size = 0.2, random_state = 42, stratify = y
    )
    print("Initialising XGBoost...")
    model = xgb.XGBClassifier(
        n_estimators = 100,
        max_depth = 6,
        learning_rate = 0.1,
        random_state = 42,
        eval_metric = 'logloss'
    )
    print("Training Model....")
    model.fit(X_train, y_train)
    print("\n --- Model Evaluation ---")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Overall Accuracy: {accuracy * 100:.2f}%\n")
    print("Detailed Classification Report: ")
    print(classification_report(y_test, y_pred, target_names = ['Benign(0)', 'Malicious(1)']))
    os.makedirs('models', exist_ok = True)
    model_path = 'models/phishguard_xgb.pkl'
    joblib.dump(model, model_path)
    print(f"\n Model Successfully serialized and saved to '{model_path}'")

if __name__ == '__main__':
    train_phishguard_model()
