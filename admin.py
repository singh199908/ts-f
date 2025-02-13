import sqlite3

# Connect to your database
with sqlite3.connect("wallet.db") as conn:
    cursor = conn.cursor()
    
    # SQL query to promote the user
    cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", ('abcd',))
    
    # Commit the changes
    conn.commit()

    print("User has been promoted to admin.")
