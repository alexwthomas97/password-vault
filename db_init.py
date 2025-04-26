import sqlite3

# Connect to the database (or create if it doesn't exist)
conn = sqlite3.connect("vault.db")
cursor = conn.cursor()

# Create table for master password (if not already)
cursor.execute("""
CREATE TABLE IF NOT EXISTS master (
    id INTEGER PRIMARY KEY,
    hashed_password BLOB NOT NULL
)
""")

# Create table for storing saved passwords
cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    encrypted_password BLOB NOT NULL
)
""")

conn.commit()
conn.close()

