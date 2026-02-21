import mysql.connector
from mysql.connector import Error

import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),          
    "password": os.getenv("DB_PASSWORD", ""),  
    "database": os.getenv("DB_NAME", "banking_db")
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
            (3, "Admin", "SYS-0000", 999999.0, 0.0, "admin_root_xyz", "0000", "System admin account."),
            (4, "Carol", "ACCT-1003", 8750.00, 12000.0, "carol_pass77", "4321", "Student loan. Good repayment history."),
            (5, "David", "ACCT-1004", 312.80, 0.0, "david_d@nk3r", "5555", "New customer. Opened account last month."),
            (6, "Eve", "ACCT-1005", 22100.50, 0.0, "eve_secure42", "6789", "Premium member. Eligible for investment products."),
            (7, "Frank", "ACCT-1006", 930.00, 3500.0, "fr@nkpass!", "1122", "Missed two payments. Under review."),
            (8, "Grace", "ACCT-1007", 15200.75, 8000.0, "grace_2024!", "9090", "Mortgage pre-approval pending."),
            (9, "Henry", "ACCT-1008", 47.25, 0.0, "h3nry_pwd", "3344", "Low balance alert triggered last week."),
            (10, "Isabel", "ACCT-1009", 6800.00, 1500.0, "izzy_secure9", "7777", "Referred by existing customer Alice."),
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