from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
import pandas as pd
import os

# Paths
PROCESSED_DATA_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/data/processed_emails.csv')
MODEL_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/optimized_phishing_model.pkl')

# Load preprocessed data
data = pd.read_csv(PROCESSED_DATA_PATH)
X = data['processed_text']  # Preprocessed text features
y = data['label']  # Target labels

# Ensure there are no NaN values in X
X = X.fillna('')  # Replace NaN values with empty strings

# Split the data into train and test sets
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Load the saved vectorizer
VECTOR_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/tfidf_vectorizer.pkl')
vectorizer = joblib.load(VECTOR_PATH)

# Transform the text data using the vectorizer
X_train_tfidf = vectorizer.transform(X_train).toarray()
X_test_tfidf = vectorizer.transform(X_test).toarray()

# Define the RandomForest model
rf_model = RandomForestClassifier(random_state=42)

# Define the parameter grid for RandomizedSearchCV
param_distributions = {
    'n_estimators': [100, 200, 300, 400],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'bootstrap': [True, False]
}

# Perform randomized search
random_search = RandomizedSearchCV(estimator=rf_model, param_distributions=param_distributions, n_iter=100, cv=3, verbose=2, random_state=42, n_jobs=-1)
random_search.fit(X_train_tfidf, y_train)

# Get the best model
best_model = random_search.best_estimator_

# Evaluate the optimized model on the test set
y_pred = best_model.predict(X_test_tfidf)
accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)

print("Optimized Model Accuracy:", accuracy)
print("Confusion Matrix:\n", conf_matrix)

# Save the optimized model
joblib.dump(best_model, MODEL_PATH)
print(f"Optimized model saved to {MODEL_PATH}")
