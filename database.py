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
                role TEXT DEFAULT 'user',
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
        
        # User roles table (for permanent role assignments)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                role_id TEXT NOT NULL,
                assigned_by INTEGER,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (assigned_by) REFERENCES users (id)
            )
        ''')
        
        # Just-In-Time permissions table - UPDATED SCHEMA
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS jit_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                permission_type TEXT NOT NULL,
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                granted_by INTEGER,
                status TEXT DEFAULT 'pending',
                reason TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (granted_by) REFERENCES users (id)
            )
        ''')
        
        # Audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action_type TEXT NOT NULL,
                resource TEXT,
                description TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Resource permissions table (defines what each role can do)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resource_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                permission TEXT NOT NULL,  -- 'read', 'write', 'delete', 'manage'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()  # Commit table creation first
        
        # Now create indexes - after tables are committed
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
        except:
            print("Note: idx_users_role index already exists or couldn't be created")
            
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_jit_permissions_expires ON jit_permissions(expires_at)')
        except:
            print("Note: idx_jit_permissions_expires index already exists or couldn't be created")
            
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_jit_permissions_user ON jit_permissions(user_id, is_active)')
        except:
            print("Note: idx_jit_permissions_user index already exists or couldn't be created")
            
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)')
        except:
            print("Note: idx_audit_logs_user index already exists or couldn't be created")
            
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)')
        except:
            print("Note: idx_audit_logs_timestamp index already exists or couldn't be created")
        
        conn.commit()
        conn.close()
        print("Database tables initialized successfully")
    
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
        """Creates a new user"""
        query = """
            INSERT INTO users (username, email, password_hash, is_verified, created_at, role)
            VALUES (?, ?, ?, ?, datetime('now'), 'user')
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
        """Saves verification code"""
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
        """Validates session token"""
        query = """
            SELECT s.*, u.username, u.email, u.is_verified, u.role
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
        """Cleans up expired verification codes and sessions"""
        try:
            # Delete expired verification codes
            self.execute_query(
                "DELETE FROM verification_codes WHERE datetime(expires_at) <= datetime('now') OR used = TRUE"
            )
            
            # Delete expired sessions
            self.execute_query(
                "DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')"
            )
            
            # Update expired JIT permissions
            self.execute_query(
                "UPDATE jit_permissions SET is_active = FALSE, status = 'expired' WHERE datetime(expires_at) <= datetime('now') AND is_active = TRUE"
            )
            
            print("Expired data cleaned up successfully")
            return True
        except Exception as e:
            print(f"Error during cleanup: {e}")
            return False
    
    def assign_user_role(self, user_id, role_id, assigned_by=None):
        """Assigns a role to a user"""
        try:
            # Update user's role in users table
            self.execute_query(
                "UPDATE users SET role = ? WHERE id = ?",
                (role_id, user_id)
            )
            
            # Log the assignment in user_roles table
            query = """
                INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
                VALUES (?, ?, ?, datetime('now'))
            """
            self.execute_query(query, (user_id, role_id, assigned_by))
            return True
        except Exception as e:
            print(f"Error assigning role: {e}")
            return False
    
    def get_user_role(self, user_id):
        """Gets user's current role"""
        query = "SELECT role FROM users WHERE id = ?"
        result = self.execute_query(query, (user_id,), fetchone=True)
        return result['role'] if result else 'user'
    
    def request_jit_permission(self, user_id, permission_type, duration_minutes, reason=None):
        """Requests JIT permission (needs admin approval)"""
        try:
            query = """
                INSERT INTO jit_permissions (user_id, permission_type, status, reason)
                VALUES (?, ?, 'pending', ?)
            """
            self.execute_query(query, (user_id, permission_type, reason))
            return True
        except Exception as e:
            print(f"Error requesting JIT permission: {e}")
            return False
    
    def approve_jit_permission(self, permission_id, granted_by, duration_minutes):
        """Approve JIT permission"""
        try:
            expires_at = datetime.now() + timedelta(minutes=duration_minutes)
            
            query = """
                UPDATE jit_permissions 
                SET status = 'approved', 
                    granted_by = ?,
                    granted_at = datetime('now'),
                    expires_at = ?,
                    is_active = TRUE
                WHERE id = ? AND status = 'pending'
            """
            self.execute_query(query, (granted_by, expires_at.strftime('%Y-%m-%d %H:%M:%S'), permission_id))
            return True
        except Exception as e:
            print(f"Error approving JIT permission: {e}")
            return False
    
    def deny_jit_permission(self, permission_id, denied_by):
        """Deny JIT permission"""
        try:
            query = """
                UPDATE jit_permissions 
                SET status = 'denied',
                    granted_by = ?,
                    is_active = FALSE
                WHERE id = ? AND status = 'pending'
            """
            self.execute_query(query, (denied_by, permission_id))
            return True
        except Exception as e:
            print(f"Error denying JIT permission: {e}")
            return False
    
    def get_pending_jit_requests(self):
        """Get all pending JIT requests"""
        query = """
            SELECT jp.*, u.username as requester_username,
                   datetime(jp.granted_at) as requested_at_formatted
            FROM jit_permissions jp
            JOIN users u ON jp.user_id = u.id
            WHERE jp.status = 'pending'
            ORDER BY jp.granted_at DESC
        """
        return self.execute_query(query, fetchall=True) or []
    
    def get_active_jit_permissions(self, user_id):
        """Gets active (approved and not expired) JIT permissions for a user"""
        query = """
            SELECT permission_type, granted_at, expires_at, reason, status,
                   datetime(granted_at) as granted_at_formatted,
                   datetime(expires_at) as expires_at_formatted
            FROM jit_permissions 
            WHERE user_id = ? AND status = 'approved' 
            AND is_active = TRUE
            AND datetime(expires_at) > datetime('now')
            ORDER BY granted_at DESC
        """
        return self.execute_query(query, (user_id,), fetchall=True) or []
    
    def has_jit_permission(self, user_id, permission_type):
        """Checks if user has active JIT permission"""
        query = """
            SELECT id FROM jit_permissions 
            WHERE user_id = ? AND permission_type = ? AND status = 'approved' 
            AND is_active = TRUE AND datetime(expires_at) > datetime('now')
        """
        result = self.execute_query(query, (user_id, permission_type), fetchone=True)
        return result is not None
    
    def log_action(self, user_id, action_type, description, resource=None, ip_address=None, user_agent=None):
        """Logs an action to audit logs"""
        try:
            query = """
                INSERT INTO audit_logs (user_id, action_type, resource, description, ip_address, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """
            self.execute_query(query, (user_id, action_type, resource, description, ip_address, user_agent))
            return True
        except Exception as e:
            print(f"Error logging action: {e}")
            return False
    
    def get_all_users_with_roles(self):
        """Gets all users with their roles"""
        query = """
            SELECT u.id, u.username, u.email, u.role, u.is_verified,
                   datetime(u.created_at) as created_at,
                   datetime(u.last_login) as last_login,
                   GROUP_CONCAT(DISTINCT jp.permission_type) as jit_permissions
            FROM users u
            LEFT JOIN jit_permissions jp ON u.id = jp.user_id AND jp.status = 'approved' AND jp.is_active = TRUE AND datetime(jp.expires_at) > datetime('now')
            GROUP BY u.id
            ORDER BY u.id DESC
        """
        return self.execute_query(query, fetchall=True) or []
    
    def get_audit_logs(self, limit=100):
        """Gets audit logs"""
        query = """
            SELECT al.*, u.username,
                   datetime(al.timestamp) as timestamp_formatted
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT ?
        """
        return self.execute_query(query, (limit,), fetchall=True) or []