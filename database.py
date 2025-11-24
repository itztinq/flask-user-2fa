import sqlite3
import os
from datetime import datetime, timedelta

class Database:
    def __init__(self):
        self.db_name = 'auth_system.db'
        self.init_database()
    
    def init_database(self):
        """Initializes the database with required tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME NULL
            )
        ''')
        
        # Verification codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                purpose TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_codes_expires ON verification_codes(expires_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
        
        conn.commit()
        conn.close()
        print("✅ Database tables initialized successfully")
    
    def get_connection(self):
        """Returns database connection"""
        return sqlite3.connect(self.db_name)
    
    def execute_query(self, query, params=(), fetchone=False, fetchall=False):
        """Executes database query"""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute(query, params)
            
            if fetchone:
                result = cursor.fetchone()
                if result:
                    result = dict(result)
            elif fetchall:
                result = cursor.fetchall()
                if result:
                    result = [dict(row) for row in result]
            else:
                result = None
            
            conn.commit()
            return result
            
        except Exception as e:
            conn.rollback()
            print(f"Database error: {e}")
            raise e
        finally:
            conn.close()
    
    def user_exists(self, username, email):
        """Checks if user already exists"""
        query = "SELECT id FROM users WHERE username = ? OR email = ?"
        return self.execute_query(query, (username, email), fetchone=True)
    
    def create_user(self, username, email, password_hash):
        """Creates a new user - UPDATED to use proper datetime"""
        query = """
            INSERT INTO users (username, email, password_hash, is_verified, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """
        try:
            self.execute_query(query, (username, email, password_hash, False))
            
            # Returns the new user's ID
            result = self.execute_query(
                "SELECT id FROM users WHERE username = ?", 
                (username,), 
                fetchone=True
            )
            return result['id'] if result else None
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username):
        """Returns user by username"""
        query = "SELECT * FROM users WHERE username = ?"
        return self.execute_query(query, (username,), fetchone=True)
    
    def get_user_by_id(self, user_id):
        """Returns user by ID"""
        query = "SELECT * FROM users WHERE id = ?"
        return self.execute_query(query, (user_id,), fetchone=True)
    
    def save_verification_code(self, user_id, code, purpose, expires_minutes=15):
        """Saves verification code - UPDATED to use proper datetime with 15min expiration"""
        expires_at = datetime.now() + timedelta(minutes=expires_minutes)
        
        query = """
            INSERT INTO verification_codes (user_id, code, purpose, expires_at, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """
        self.execute_query(query, (user_id, code, purpose, expires_at.strftime('%Y-%m-%d %H:%M:%S')))
    
    def verify_code(self, user_id, code, purpose):
        """Verifies code and marks it as used"""
        query = """
            SELECT id FROM verification_codes 
            WHERE user_id = ? AND code = ? AND purpose = ? 
            AND datetime(expires_at) > datetime('now') AND used = FALSE
        """
        
        code_record = self.execute_query(
            query, (user_id, code, purpose), fetchone=True
        )
        
        if code_record:
            update_query = "UPDATE verification_codes SET used = TRUE WHERE id = ?"
            self.execute_query(update_query, (code_record['id'],))
            return True
        
        return False
    
    def create_session(self, user_id, session_token, expires_hours=24):
        """Creates a new session"""
        expires_at = datetime.now() + timedelta(hours=expires_hours)
        
        query = """
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """
        try:
            self.execute_query(query, (user_id, session_token, expires_at.strftime('%Y-%m-%d %H:%M:%S')))
            
            # Update last_login with proper datetime
            self.execute_query(
                "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                (user_id,)
            )
            return True
        except Exception as e:
            print(f"Error creating session: {e}")
            return False
    
    def validate_session(self, session_token):
        """Validates session token - UPDATED to use datetime comparison"""
        query = """
            SELECT s.*, u.username, u.email, u.is_verified
            FROM sessions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.session_token = ? AND datetime(s.expires_at) > datetime('now') AND u.is_verified = TRUE
        """
        
        return self.execute_query(query, (session_token,), fetchone=True)
    
    def delete_session(self, session_token):
        """Deletes session"""
        self.execute_query(
            "DELETE FROM sessions WHERE session_token = ?", 
            (session_token,)
        )
    
    def activate_user(self, user_id):
        """Activates user after verification"""
        self.execute_query(
            "UPDATE users SET is_verified = TRUE WHERE id = ?", 
            (user_id,)
        )
    
    def cleanup_expired_data(self):
        """Cleans up expired verification codes and sessions - UPDATED to use datetime"""
        try:
            # Delete expired verification codes
            self.execute_query(
                "DELETE FROM verification_codes WHERE datetime(expires_at) <= datetime('now') OR used = TRUE"
            )
            
            # Delete expired sessions
            self.execute_query(
                "DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')"
            )
            
            print("✅ Expired data cleaned up successfully")
            return True
        except Exception as e:
            print(f"Error during cleanup: {e}")
            return False
    
    def get_database_stats(self):
        """Gets database statistics for admin panel"""
        stats = {}
        
        # User count
        result = self.execute_query("SELECT COUNT(*) as count FROM users", fetchone=True)
        stats['total_users'] = result['count'] if result else 0
        
        # Verified users
        result = self.execute_query("SELECT COUNT(*) as count FROM users WHERE is_verified = TRUE", fetchone=True)
        stats['verified_users'] = result['count'] if result else 0
        
        # Active sessions
        result = self.execute_query("SELECT COUNT(*) as count FROM sessions WHERE datetime(expires_at) > datetime('now')", fetchone=True)
        stats['active_sessions'] = result['count'] if result else 0
        
        return stats