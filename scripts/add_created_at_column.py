import sqlite3

def add_created_at_column():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        # Create a new users_temp table with the created_at column
        c.execute('''
            CREATE TABLE users_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Copy data from old users table to the new users_temp table
        c.execute('''
            INSERT INTO users_temp (id, email, password)
            SELECT id, email, password FROM users
        ''')

        # Drop the old users table
        c.execute('DROP TABLE users')

        # Rename users_temp to users
        c.execute('ALTER TABLE users_temp RENAME TO users')

        conn.commit()
        print("created_at column added and data migrated successfully.")
    
    except sqlite3.Error as e:
        print(f"Error updating table: {e}")
    
    finally:
        conn.close()

if __name__ == '__main__':
    add_created_at_column()
