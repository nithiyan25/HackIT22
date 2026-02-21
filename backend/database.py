import mysql.connector
from mysql.connector import Error

# IMPORTANT: Change "password" to your actual MySQL root password
DB_CONFIG = {
    "host": "localhost",
    "user": "root",          
    "password": "2501",  
    "database": "banking_db"
}

def get_db_connection():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"]
    )

def setup_database():
    try:
        # Connect without DB name to auto-create it
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        cursor = conn.cursor()
        db_name = DB_CONFIG["database"]
        
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        cursor.execute(f"USE {db_name}")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                customer_id INT PRIMARY KEY,
                name VARCHAR(50),
                account_number VARCHAR(20),
                balance FLOAT,
                loan_amount FLOAT,
                password VARCHAR(50),
                pin VARCHAR(10),
                internal_notes TEXT
            )
        """)
        
        cursor.execute("TRUNCATE TABLE customers")
        
        sample_data = [
            (1, "Alice", "ACCT-1001", 5432.10, 0.0, "alice_pwd123", "1234", "High net worth. Pre-approved for loan."),
            (2, "Bob", "ACCT-1002", 120.50, 5000.0, "bob_secure!9", "9876", "Late on loan payments."),
            (3, "Admin", "SYS-0000", 999999.0, 0.0, "admin_root_xyz", "0000", "System admin account.")
        ]
        
        cursor.executemany("""
            INSERT INTO customers (customer_id, name, account_number, balance, loan_amount, password, pin, internal_notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, sample_data)
        
        conn.commit()
        print(f"✅ Database '{db_name}' auto-created and seeded successfully.")
        
    except Error as e:
        print(f"❌ Error connecting to MySQL: {e}")
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()