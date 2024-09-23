import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import os

# Load preprocessed data
DATA_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/data/processed_emails.csv')
data = pd.read_csv(DATA_PATH)

# Ensure no NaN values in the email text data
data['processed_text'] = data['processed_text'].fillna('')

# Split data into training and testing sets
X = data['processed_text']
y = data['label']  # Assuming 'label' column is 1 for phishing, 0 for non-phishing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Load vectorizer
VECTORIZER_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/tfidf_vectorizer.pkl')
vectorizer = joblib.load(VECTORIZER_PATH)

# Transform text data to numerical data
X_train_tfidf = vectorizer.transform(X_train).toarray()
X_test_tfidf = vectorizer.transform(X_test).toarray()

# Initialize RandomForest model
model = RandomForestClassifier()

# Train the model
model.fit(X_train_tfidf, y_train)

# Make predictions
y_pred = model.predict(X_test_tfidf)

# Model evaluation
accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)

print(f"Accuracy: {accuracy}")
print(f"Confusion Matrix:\n {conf_matrix}")

# Save the trained model
MODEL_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/phishing_model.pkl')
joblib.dump(model, MODEL_PATH)
print(f"Model saved to {MODEL_PATH}")
