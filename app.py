from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash
import secrets
import random
from datetime import datetime, timedelta
import re
from werkzeug.security import generate_password_hash, check_password_hash

from database import Database

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-change-in-production-2024'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

db = Database()

# Email configuration
EMAIL_CONFIG = {
    'enabled': True,
    'simulation_mode': True
}

# Admin configuration (AdminPass123!)
ADMIN_CONFIG = {
    'admin_username': 'admin',
    'admin_email': 'admin@auth-system.com'
}

# Context processor for EMAIL_CONFIG
@app.context_processor
def inject_email_config():
    return dict(EMAIL_CONFIG=EMAIL_CONFIG)

class AuthSystem:
    @staticmethod
    def validate_email(email):
        """Email format validation"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False, "Invalid email format. Use: your_name@domain.com"
        
        return True, "Email is valid"
    
    @staticmethod
    def validate_password(password):
        """Password validation"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>-_]", password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    
    @staticmethod
    def generate_verification_code():
        """Generates 6-digit code"""
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def generate_session_token():
        """Generates secure session token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def send_verification_email(email, code, purpose):
        """Sends verification email (terminal only)"""
        if not EMAIL_CONFIG['enabled']:
            return True
            
        if EMAIL_CONFIG['simulation_mode']:
            print(f"\n=== VERIFICATION CODE ===")
            print(f"To: {email}")
            print(f"Purpose: {purpose}")
            print(f"Code: {code}")
            print(f"Valid for: 10 minutes")
            print(f"=====================\n")
            return True
        else:
            try:
                return True
            except Exception as e:
                print(f"Email sending error: {e}")
                return False

# Create admin user on startup
def create_admin_user():
    """Creates admin user if doesn't exist"""
    admin_exists = db.get_user_by_username(ADMIN_CONFIG['admin_username'])
    if not admin_exists:
        admin_password_hash = generate_password_hash('AdminPass123!')
        admin_id = db.create_user(
            ADMIN_CONFIG['admin_username'],
            ADMIN_CONFIG['admin_email'],
            admin_password_hash
        )
        db.activate_user(admin_id)
        print(f"✅ Admin user created: {ADMIN_CONFIG['admin_username']} / AdminPass123!")
    else:
        print(f"✅ Admin user already exists")

# Authentication middleware
@app.before_request
def check_auth():
    """Authentication middleware"""
    public_routes = ['login', 'register', 'verify_email', 'verify_login', 'static']
    
    if request.endpoint in public_routes:
        return
    
    session_token = request.cookies.get('session_token')
    if session_token:
        session_data = db.validate_session(session_token)
        if session_data:
            session['user_id'] = session_data['user_id']
            session['username'] = session_data['username']
            session['is_admin'] = (session_data['username'] == ADMIN_CONFIG['admin_username'])
            return
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

def is_admin():
    """Check if current user is admin"""
    return session.get('is_admin', False)

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Prevent registering as admin
        if username.lower() == ADMIN_CONFIG['admin_username'].lower():
            flash('This username is reserved', 'error')
            return render_template('register.html')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        email_valid, email_message = AuthSystem.validate_email(email)
        if not email_valid:
            flash(email_message, 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        is_valid, message = AuthSystem.validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')
        
        if db.user_exists(username, email):
            flash('Username or email already exists', 'error')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        
        try:
            user_id = db.create_user(username, email, password_hash)
            
            verification_code = AuthSystem.generate_verification_code()
            db.save_verification_code(user_id, verification_code, 'registration')
            
            if AuthSystem.send_verification_email(email, verification_code, 'registration'):
                session['pending_user_id'] = user_id
                return redirect(url_for('verify_email'))
            else:
                flash('Error sending verification code', 'error')
                return render_template('register.html')
                
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    pending_user_id = session.get('pending_user_id')
    
    if not pending_user_id:
        flash('Please start registration again', 'error')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code or len(code) != 6 or not code.isdigit():
            flash('Please enter a valid 6-digit code', 'error')
            return render_template('verify_email.html')
        
        if db.verify_code(pending_user_id, code, 'registration'):
            db.activate_user(pending_user_id)
            session.pop('pending_user_id', None)
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired code. Please try again.', 'error')
            return render_template('verify_email.html')
    
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter username and password', 'error')
            return render_template('login.html')
        
        user = db.get_user_by_username(username)
        
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        
        if not user['is_verified']:
            flash('Your account is not verified. Please check your email.', 'error')
            return render_template('login.html')
        
        login_code = AuthSystem.generate_verification_code()
        db.save_verification_code(user['id'], login_code, 'login')
        
        if AuthSystem.send_verification_email(user['email'], login_code, 'login'):
            session['pending_login_user_id'] = user['id']
            return redirect(url_for('verify_login'))
        else:
            flash('Error sending login code', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/verify-login', methods=['GET', 'POST'])
def verify_login():
    pending_user_id = session.get('pending_login_user_id')
    
    if not pending_user_id:
        flash('Please start login again', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code or len(code) != 6 or not code.isdigit():
            flash('Please enter a valid 6-digit code', 'error')
            return render_template('verify_login.html')
        
        if db.verify_code(pending_user_id, code, 'login'):
            session_token = AuthSystem.generate_session_token()
            db.create_session(pending_user_id, session_token)
            
            user = db.get_user_by_id(pending_user_id)
            
            session['user_id'] = pending_user_id
            session['username'] = user['username']
            session['is_admin'] = (user['username'] == ADMIN_CONFIG['admin_username'])
            session.pop('pending_login_user_id', None)
            
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie(
                'session_token', 
                session_token,
                httponly=True,
                secure=app.config['SESSION_COOKIE_SECURE'],
                samesite=app.config['SESSION_COOKIE_SAMESITE'],
                max_age=24*3600
            )
            
            flash('Login successful!', 'success')
            return response
        else:
            flash('Invalid or expired code. Please try again.', 'error')
            return render_template('verify_login.html')
    
    return render_template('verify_login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.get_user_by_id(session['user_id'])
    
    # UPDATED: Proper datetime handling - no more timestamp conversion
    if user['last_login']:
        last_login = user['last_login']  # Now it's already a proper datetime string
    else:
        last_login = "First login"
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         email=user['email'],
                         last_login=last_login,
                         is_admin=session.get('is_admin', False))

@app.route('/admin/db-viewer')
def db_viewer():
    """Database viewer - ADMIN ONLY"""
    if not session.get('is_admin', False):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all users - INCLUDING PASSWORD HASHES
        users = db.execute_query("""
            SELECT id, username, email, password_hash, is_verified,
                   datetime(created_at) as created_at_formatted,
                   CASE 
                       WHEN last_login IS NULL THEN 'Never' 
                       ELSE datetime(last_login) 
                   END as last_login_formatted
            FROM users 
            ORDER BY id DESC
        """, fetchall=True)
        
        # Get verification codes (last 20)
        verification_codes = db.execute_query("""
            SELECT vc.*, u.username,
                   datetime(vc.expires_at) as expires_at_formatted,
                   datetime(vc.created_at) as created_at_formatted
            FROM verification_codes vc
            LEFT JOIN users u ON vc.user_id = u.id
            ORDER BY vc.id DESC 
            LIMIT 20
        """, fetchall=True)
        
        # Get active sessions
        sessions = db.execute_query("""
            SELECT s.*, u.username,
                   datetime(s.expires_at) as expires_at_formatted,
                   datetime(s.created_at) as created_at_formatted
            FROM sessions s 
            LEFT JOIN users u ON s.user_id = u.id
            WHERE datetime(s.expires_at) > datetime('now') 
            ORDER BY s.id DESC
        """, fetchall=True)
        
        # Clean up expired data automatically when admin views the page
        db.cleanup_expired_data()
        
        return render_template('db_viewer.html', 
                             users=users or [],
                             verification_codes=verification_codes or [], 
                             sessions=sessions or [])
    
    except Exception as e:
        flash(f'Error accessing database: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    
    if session_token:
        db.delete_session(session_token)
    
    session.clear()
    
    response = make_response(redirect(url_for('login')))
    response.set_cookie('session_token', '', expires=0)
    
    flash('Logout successful!', 'success')
    return response

# Create admin user when app starts
with app.app_context():
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)