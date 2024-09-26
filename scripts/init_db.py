import os
import sqlite3
import bcrypt

# Function to initialize the database
def init_db():
    db_path = os.path.join(os.getcwd(), 'users.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create the 'users' table with 'created_at' column
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    # Create the 'detection_history' table
    c.execute('''CREATE TABLE IF NOT EXISTS detection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    email_text TEXT,
                    result TEXT,
                    detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )''')

    conn.commit()
    conn.close()
    print(f"Database initialized successfully at {db_path}.")

# Function to insert a user into the 'users' table with hashed password and created_at timestamp
def insert_user(email, password):
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return
    if not any(char.isdigit() for char in password):
        print("Password must contain at least one number.")
        return
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        print(f"User {email} added successfully.")
    except sqlite3.IntegrityError:
        print(f"User {email} already exists.")
    except sqlite3.Error as e:
        print(f"Error inserting user: {e}")
    conn.close()

# Function to insert detection history for a user
def insert_detection_history(user_id, email_text, result):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO detection_history (user_id, email_text, result) VALUES (?, ?, ?)", 
                  (user_id, email_text, result))
        conn.commit()
        print(f"Detection history added for user_id {user_id}.")
    except sqlite3.Error as e:
        print(f"Error inserting detection history: {e}")
    conn.close()

# Function to fetch all detection history for a user
def fetch_detection_history(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM detection_history WHERE user_id = ?", (user_id,))
        history = c.fetchall()

        # Get column names to format output
        column_names = [desc[0] for desc in c.description]
        formatted_history = [dict(zip(column_names, row)) for row in history]
    except sqlite3.Error as e:
        print(f"Error fetching detection history: {e}")
        formatted_history = []
    conn.close()

    return formatted_history

# Function to fetch a user by email (for authentication purposes)
def fetch_user_by_email(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
    except sqlite3.Error as e:
        print(f"Error fetching user: {e}")
        user = None
    conn.close()
    return user

# Function to check if the tables exist in the database
def check_table_exists():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    try:
        # Check for 'users' table
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        users_table_exists = c.fetchone()

        # Check for 'detection_history' table
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='detection_history';")
        history_table_exists = c.fetchone()

        # Output the results
        if users_table_exists:
            print("Table 'users' exists.")
        else:
            print("Table 'users' does not exist.")

        if history_table_exists:
            print("Table 'detection_history' exists.")
        else:
            print("Table 'detection_history' does not exist.")
    except sqlite3.Error as e:
        print(f"Error checking table existence: {e}")
    conn.close()

if __name__ == "__main__":
    init_db()  # Initialize the database and create tables
    check_table_exists()  # Check if tables exist

    # Insert sample user and detection history data
    insert_user('testuser@example.com', 'password123')

    # Assuming user ID 1 (you may need to adjust based on your actual IDs)
    insert_detection_history(1, "Sample phishing email content", "Phishing")

    # Fetch and print detection history for user ID 1
    history = fetch_detection_history(1)
    print("Detection History for User ID 1:", history)
