import sqlite3
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import qrcode

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Make sure to change this to a secure key for production
bcrypt = Bcrypt(app)
CORS(app)

def init_db():
    with sqlite3.connect("wallet.db") as conn:
        cursor = conn.cursor()
        
        # Add the new 'role' column if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                balance REAL DEFAULT 0.0,
                role TEXT DEFAULT 'user'  -- Default role is 'user'
            )
        ''')

        # Remove 'is_admin' if it exists
        try:
            cursor.execute("ALTER TABLE users DROP COLUMN is_admin")
        except sqlite3.OperationalError:
            pass  # Ignore if column doesn't exist
        
        conn.commit()

def get_user_by_id(user_id):
    connection = sqlite3.connect("wallet.db")  # Update with your DB file
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()  # Returns (id, username, email, balance, role)
    connection.close()
    return user

@app.route("/")
def home():
    return render_template("index.html")  # Index page will act as login page

QR_FOLDER = "static/qr_codes"
os.makedirs(QR_FOLDER, exist_ok=True)

# User Registration Route
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not (username and password and email):
        return jsonify({"error": "All fields are required."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    default_role = "user"  # All new users start as 'user'

    with sqlite3.connect("wallet.db") as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                           (username, hashed_password, email, default_role))
            conn.commit()
            return jsonify({"message": "User registered successfully."}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username already exists."}), 409

# User Login Route
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    with sqlite3.connect("wallet.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            session.clear()  # Clear old session data
            session["user_id"] = user[0]
            session["role"] = user[3]  # Store role in session
            print(f"DEBUG: Logged in as {user[1]}, Role: {user[3]}")  # Debugging print
            return jsonify({"message": "Login successful", "role": session["role"]}), 200
        else:
            return jsonify({"error": "Invalid username or password."}), 401

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for("home"))

    user_data = None
    users = None

    try:
        conn = sqlite3.connect("wallet.db")
        cursor = conn.cursor()
        print(f"DEBUG: Session user_id = {session.get('user_id')}")  # Debugging print

        # ✅ Fetch user directly from the database
        cursor.execute("SELECT id, username, email, balance, role FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        print("User Data:", user)

        if user:  # Ensure user exists before proceeding
            role = user[4]  # ✅ Use fetched user directly
            user_data = {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "balance": user[3],
                "role": role
            }

            print(f"DEBUG: User Role = {user_data['role']}")  # Debugging print

            if role == "admin":
                cursor.execute("SELECT id, username, email, balance FROM users")
                users = cursor.fetchall() or []  # Ensure users is not None
                return render_template("dashboard.html", users=users, role="admin", user=user_data)

            elif role == "manager":
                cursor.execute("SELECT id, username, email, balance FROM users")
                users = cursor.fetchall() or []
                return render_template("dashboard.html", users=users, role="manager", user=user_data)

            else:  # Regular user
                qr_path = generate_qr(user_data["id"])
                return render_template("dashboard.html", user=user_data, role=role, qr_path=qr_path)

    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        conn.close()

    return redirect(url_for("home"))  # Redirect to home if user_data is None

# Route to display the balance editing form
@app.route("/edit_balance", methods=["GET", "POST"])
def edit_balance():
    if 'user_id' not in session or not session.get("role") == "admin":
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("edit_balance.html")

    username = request.form.get("username")
    new_balance = request.form.get("balance")

    if not username or not new_balance:
        return render_template("edit_balance.html", error="Username and balance are required.")

    try:
        new_balance = float(new_balance)
        with sqlite3.connect("wallet.db") as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
            conn.commit()
            if cursor.rowcount == 0:
                return render_template("edit_balance.html", error=f"User '{username}' not found.")
            return render_template("edit_balance.html", message=f"Balance of user '{username}' updated to {new_balance}.")
    except ValueError:
        return render_template("edit_balance.html", error="Invalid balance value.")
@app.route("/deduct_balance", methods=["POST"])
def deduct_balance():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 403

    if session.get("role") != "manager":
        return jsonify({"error": "Access denied. Managers only."}), 403

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400

        user_id = data.get("userId")  # The scanned QR data
        amount = data.get("amount")

        print(f"📌 Received User ID: {user_id} (Type: {type(user_id)})")  # Debugging log

        if not user_id or not amount:
            return jsonify({"error": "User ID and amount are required"}), 400

        # Ensure user_id is a valid integer
        try:
            user_id = int(user_id)  # Convert to integer
        except ValueError:
            print(f"❌ ERROR: Cannot convert '{user_id}' to integer!")  # Debugging log
            return jsonify({"error": "Invalid user ID format"}), 400

        amount = float(amount)

        with sqlite3.connect("wallet.db") as conn:
            cursor = conn.cursor()

            # Check if the user exists in the database
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            found_user = cursor.fetchone()

            if not found_user:
                print(f"❌ User ID {user_id} not found in database!")  # Debugging log
                return jsonify({"error": "User not found"}), 404

            # Deduct balance if user exists
            cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
            conn.commit()

            return jsonify({"message": f"Deducted ${amount} from user {user_id}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# Function to generate QR code
def generate_qr(user_id):
    qr_data = f"wallet_user:{user_id}"
    qr = qrcode.make(qr_data)
    qr_path = os.path.join(QR_FOLDER, f"{user_id}.png")
    qr.save(qr_path)
    return qr_path

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=8080)
