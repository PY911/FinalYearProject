import joblib
from nltk.tokenize import word_tokenize
import os

# Paths to the optimized model and vectorizer
MODEL_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/optimized_phishing_model.pkl')
VECTOR_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models/tfidf_vectorizer.pkl')

# Load the optimized model and vectorizer
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTOR_PATH)

# Function to preprocess new email text
def preprocess_text(text):
    tokens = word_tokenize(text.lower())
    filtered_tokens = [word for word in tokens if word.isalnum()]
    return ' '.join(filtered_tokens)

# Function to make predictions on new email text
def predict_email(email_text):
    # Preprocess the email text
    processed_email = preprocess_text(email_text)
    
    # Vectorize the email text
    email_vector = vectorizer.transform([processed_email])
    
    # Predict using the optimized model
    prediction = model.predict(email_vector)
    
    # Output the prediction result
    if prediction[0] == 1:
        return "Phishing Email Detected"
    else:
        return "Non-Phishing Email"

# Example: Predict an input email
if __name__ == "__main__":
    email_text = input("Enter the email text to classify: ")
    result = predict_email(email_text)
    print(result)
