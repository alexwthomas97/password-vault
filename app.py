import os
from flask import Flask, render_template, request, redirect, session
import sqlite3, bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Create or load encryption key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("secret.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

# Ensure database and table exist
conn = sqlite3.connect("vault.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS master (id INTEGER PRIMARY KEY, hashed_password BLOB)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    encrypted_password BLOB
)''')
conn.commit()
conn.close()

@app.route("/", methods=["GET", "POST"])
def login():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master WHERE id = 1")
    result = cursor.fetchone()

    if request.method == "POST":
        entered_pw = request.form["master_password"].encode("utf-8")
        if result:
            if bcrypt.checkpw(entered_pw, result[1]):
                session["user"] = True
                return redirect("/vault")
            else:
                return "Incorrect password"
        else:
            hashed = bcrypt.hashpw(entered_pw, bcrypt.gensalt())
            cursor.execute("INSERT INTO master (id, hashed_password) VALUES (1, ?)", (hashed,))
            conn.commit()
            session["user"] = True
            return redirect("/vault")

    return render_template("login.html")

@app.route("/vault", methods=["GET", "POST"])
def vault():
    if not session.get("user"):
        return redirect("/")

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    if request.method == "POST":
        name = request.form["name"]
        password = request.form["password"]
        encrypted = fernet.encrypt(password.encode("utf-8"))
        cursor.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (name, encrypted))
        conn.commit()

    cursor.execute("SELECT id, name, encrypted_password FROM passwords")
    results = cursor.fetchall()
    decrypted = [(row[0], row[1], fernet.decrypt(row[2]).decode("utf-8")) for row in results]

    return render_template("vault.html", passwords=decrypted)

@app.route("/edit/<int:id>", methods=["POST"])
def edit(id):
    print("🚨 Edit route triggered!")  # NEW
    print("Received ID:", id)          # NEW
    print("Form data:", request.form)  # NEW

    if not session.get("user"):
        return redirect("/")

    new_name = request.form.get("name")
    new_password = request.form.get("password")

    if not new_name or not new_password:
        return redirect("/vault")  # If empty, don't update

    encrypted = fernet.encrypt(new_password.encode("utf-8"))

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET name = ?, encrypted_password = ? WHERE id = ?", (new_name, encrypted, id))
    conn.commit()
    print("✅ Updated in database!")  # Correctly placed here
    conn.close()

    return redirect("/vault")

@app.route("/delete/<int:id>", methods=["POST"])
def delete(id):
    if not session.get("user"):
        return redirect("/")

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (id,))
    conn.commit()
    return redirect("/vault")

if __name__ == "__main__":
    app.run(debug=True)




