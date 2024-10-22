import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
import bcrypt  # For password hashing
import joblib
import textract
import docx
import numpy as np
import logging
import re
import string
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

# User authentication setup
app.secret_key = os.getenv('SECRET_KEY', '1234')  # Use environment variable for secret key

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page when not logged in

# Serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.secret_key)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Database Setup
def get_db_connection():
    try:
        conn = sqlite3.connect('users.db')  # Connect to SQLite database
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None

def create_users_table():
    conn = get_db_connection()
    if conn:
        try:
            # Ensure users table exists
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                email TEXT UNIQUE NOT NULL,
                                password TEXT NOT NULL
                            )''')
            # Ensure detection_history table exists
            conn.execute('''CREATE TABLE IF NOT EXISTS detection_history (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                email_text TEXT,
                                result TEXT,
                                detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                            )''')
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")
        finally:
            conn.close()

# Load the trained model and vectorizer
MODEL_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models', 'optimized_phishing_model.pkl')
VECTORIZER_PATH = os.path.join(os.getcwd(), 'C:/Users/SilasX/Desktop/PhishingDetectionProject/models', 'tfidf_vectorizer.pkl')

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# Clean the email text input
def clean_input_text(text):
    return text.strip()

# Text Preprocessing
def preprocess_text(text):
    text = text.lower()
    text = re.sub(r'http\S+', '', text)  # Remove URLs
    text = text.translate(str.maketrans('', '', string.punctuation))  # Remove punctuation
    words = word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    words = [word for word in words if word not in stop_words]
    return ' '.join(words)

# Security Tips Based on Prediction
security_tips = {
    0: "This email appears safe. Always remain cautious and verify unexpected emails.",
    1: "Do not click any links or download attachments. Report this email to your security team."
}

# Landing Page Route
@app.route('/')
def home():
    return redirect(url_for('landing'))

@app.route('/landing')
def landing():
    return render_template('landing.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        conn = get_db_connection()
        if conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                user_obj = User(user['id'])
                login_user(user_obj)
                flash('Successfully logged in.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect email or password. Please try again.', 'danger')  # Flash the error message
    return render_template('login.html')

# Logout Route
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Sign Up Route
@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        if conn:
            try:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if user:
                    flash('User already exists. Please login.', 'danger')
                else:
                    conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
                    conn.commit()
                    flash('Account created successfully.', 'success')
                    conn.close()
                    return redirect(url_for('sign_up_confirmation'))  # Redirect to confirmation page
            except sqlite3.Error as e:
                logging.error(f"Error during sign-up: {e}")
                flash('Error creating account. Please try again.', 'danger')
            finally:
                conn.close()
    return render_template('sign_up.html')

# Confirmation route to display success message and auto-redirect
@app.route('/sign_up_confirmation')
def sign_up_confirmation():
    return render_template('sign_up_confirmation.html')



# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        
        conn = get_db_connection()
        if conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if not user:
                flash('Email not found.', 'danger')
            else:
                # Generate a secure token (for demo purposes, we're using this, but you'd email this link)
                token = serializer.dumps(email, salt='password-reset')
                reset_url = url_for('reset_password', token=token, _external=True)

                # Flash the clickable link
                flash(f'A password reset link has been sent to your email. '
                      f'(For demo, the link is: <a href="{reset_url}">Click here to reset your password</a>)', 'info')
    return render_template('forgot_password.html')

# Reset Password Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()

        # Render reset_password template with success message instead of redirecting to the index
        flash('Password reset successful. Please login.', 'success')
        return render_template('reset_password.html', success=True, token=token)

    return render_template('reset_password.html', token=token)

# Update Password Route
@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        if conn:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()

            if user and bcrypt.checkpw(current_password.encode('utf-8'), user['password']):  # Remove .encode if password is already in bytes
                if new_password == confirm_password:
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
                    conn.commit()
                    flash('Password updated successfully.', 'success')
                else:
                    flash('New passwords do not match.', 'danger')
            else:
                flash('Current password is incorrect.', 'danger')

            conn.close()
        return redirect(url_for('update_password'))

    return render_template('update_password.html')

# Index (Main Dashboard) Route
@app.route('/index')
@login_required
def index():
    return render_template('index.html')

# Predict Phishing Route (Text Input)
@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        email_text = request.form['email_text']
        cleaned_text = clean_input_text(email_text)
        processed_text = preprocess_text(cleaned_text)
        email_vector = vectorizer.transform([processed_text]).toarray()

        prediction = model.predict(email_vector)[0]  # Get the single prediction value
        
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(email_vector)
            confidence = probabilities.max() * 100  # Get the maximum confidence percentage
        else:
            confidence = "N/A"

        conn = get_db_connection()
        if conn:
            conn.execute('INSERT INTO detection_history (user_id, email_text, result) VALUES (?, ?, ?)', 
                         (current_user.id, email_text, f"{'Phishing' if prediction else 'Non-Phishing'} (Confidence: {confidence:.2f}%)"))
            conn.commit()
            conn.close()

        # Render template with prediction and security tips
        return render_template('index.html', 
                               prediction_text=f"{'Phishing' if prediction else 'Non-Phishing'} Email (Confidence: {confidence:.2f}%)",
                               confidence=confidence,
                               security_tip=security_tips[prediction])

    except Exception as e:
        logging.error(f"Error during phishing detection: {e}")
        return render_template('index.html', prediction_text=f"Error: {str(e)}")

# File Upload and Phishing Detection Route
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        file = request.files['file']
        file_ext = file.filename.split('.')[-1].lower()
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)

        if file_ext == 'txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                email_text = f.read()
        elif file_ext == 'pdf':
            email_text = textract.process(file_path, method='pdftotext').decode('utf-8')
        elif file_ext == 'docx':
            doc = docx.Document(file_path)
            email_text = '\n'.join([para.text for para in doc.paragraphs])
        elif file_ext == 'doc':
            email_text = textract.process(file_path).decode('utf-8')
        else:
            raise Exception("Unsupported file format")

        cleaned_text = clean_input_text(email_text)
        processed_text = preprocess_text(cleaned_text)
        email_vector = vectorizer.transform([processed_text]).toarray()

        prediction = model.predict(email_vector)[0]

        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(email_vector)
            confidence = probabilities.max() * 100
        else:
            confidence = "N/A"

        conn = get_db_connection()
        if conn:
            conn.execute('INSERT INTO detection_history (user_id, email_text, result) VALUES (?, ?, ?)', 
                         (current_user.id, email_text, f"{'Phishing' if prediction else 'Non-Phishing'} (Confidence: {confidence:.2f}%)"))
            conn.commit()
            conn.close()

        return render_template('index.html', 
                               prediction_text=f"{'Phishing' if prediction else 'Non-Phishing'} Email (Confidence: {confidence:.2f}%)",
                               confidence=confidence,
                               security_tip=security_tips[prediction])

    except Exception as e:
        logging.error(f"Error during file upload: {e}")
        return render_template('index.html', prediction_text=f"Error: {str(e)}")

# Detection History Route
@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    if conn:
        history = conn.execute('SELECT * FROM detection_history WHERE user_id = ?', (current_user.id,)).fetchall()
        conn.close()
        return render_template('history.html', history=history)
    else:
        flash('Error fetching history', 'danger')
        return redirect(url_for('index'))

# Clear Detection History Route
@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    conn = get_db_connection()
    if conn:
        conn.execute('DELETE FROM detection_history WHERE user_id = ?', (current_user.id,))
        conn.commit()
        conn.close()
        flash('Detection history cleared.', 'info')
    return redirect(url_for('history'))

# Profile Route
@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    if conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
        phishing_files_checked = conn.execute('SELECT COUNT(*) FROM detection_history WHERE user_id = ?', (current_user.id,)).fetchone()[0]
        conn.close()

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('index'))

        return render_template('profile.html', user=user, phishing_files_checked=phishing_files_checked)
    else:
        flash('Error fetching user profile.', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)
