# Save this as read_db.py
import sqlite3
import sys

def read_auth_database():
    try:
        # Connect to the database
        conn = sqlite3.connect('auth_system.db')
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("Tables in auth_system.db:")
        print("-" * 40)
        for table in tables:
            print(f"• {table[0]}")
        
        # Show data from each table
        for table in tables:
            table_name = table[0]
            print(f"\n\nData from '{table_name}' table:")
            print("-" * 60)
            
            try:
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                col_names = [col[1] for col in columns]
                print("Columns:", ", ".join(col_names))
                
                # Get all rows
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # Display rows
                for i, row in enumerate(rows, 1):
                    print(f"\nRow {i}:")
                    for col_name, value in zip(col_names, row):
                        print(f"  {col_name}: {value}")
                        
            except Exception as e:
                print(f"  Error reading table: {e}")
        
        conn.close()
        
    except sqlite3.OperationalError:
        print("Error: Could not open 'auth_system.db'")
        print("Make sure the file exists in the current directory.")
        print("Current directory contains:")
        import os
        for file in os.listdir('.'):
            print(f"  {file}")

if __name__ == "__main__":
    read_auth_database()