from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash
import secrets
import random
from datetime import datetime, timedelta
import re
from werkzeug.security import generate_password_hash, check_password_hash

from database import Database

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-change-in-production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

db = Database()

# Email configuration
EMAIL_CONFIG = {
    'enabled': True,
    'simulation_mode': True
}

# Admin configuration
ADMIN_CONFIG = {
    'admin_username': 'admin',
    'admin_email': 'admin@auth-system.com'
}

# Organizational Roles (Global)
ORGANIZATIONAL_ROLES = {
    'system_admin': {
        'name': 'System Administrator',
        'level': 100,
        'description': 'Full system access including user management and role assignment',
        'permissions': ['*']
    },
    'org_admin': {
        'name': 'Organization Administrator',
        'level': 90,
        'description': 'Organization-level management access',
        'permissions': ['user_management', 'role_view', 'audit_logs', 'reports']
    },
    'department_manager': {
        'name': 'Department Manager',
        'level': 80,
        'description': 'Department-level access for team management',
        'permissions': ['team_management', 'reports']
    },
    'senior_developer': {
        'name': 'Senior Developer',
        'level': 70,
        'description': 'Full development access to all resources',
        'permissions': ['database_access', 'api_access', 'deployment']
    },
    'developer': {
        'name': 'Developer',
        'level': 60,
        'description': 'Standard development access',
        'permissions': ['database_access', 'api_access']
    },
    'security_auditor': {
        'name': 'Security Auditor',
        'level': 50,
        'description': 'Read-only access for security auditing',
        'permissions': ['audit_logs', 'user_view', 'role_view']
    },
    'user': {
        'name': 'Regular User',
        'level': 10,
        'description': 'Basic user access',
        'permissions': ['dashboard', 'profile']
    }
}

# Resource-Specific Roles (JIT)
RESOURCE_ROLES = {
    'database_admin': {
        'name': 'Database Administrator',
        'level': 95,
        'description': 'Full database management access',
        'resource': 'database',
        'permissions': ['read', 'write', 'delete', 'manage']
    },
    'database_writer': {
        'name': 'Database Writer',
        'level': 85,
        'description': 'Write access to databases',
        'resource': 'database',
        'permissions': ['read', 'write']
    },
    'database_reader': {
        'name': 'Database Reader',
        'level': 75,
        'description': 'Read-only access to databases',
        'resource': 'database',
        'permissions': ['read']
    },
    'backup_admin': {
        'name': 'Backup Administrator',
        'level': 65,
        'description': 'Backup system management',
        'resource': 'backup',
        'permissions': ['read', 'write', 'execute']
    }
}

# Resource Definitions
RESOURCES = {
    'dashboard': 'User Dashboard',
    'user_management': 'User Management System',
    'role_management': 'Role Management System',
    'database_viewer': 'Database Viewer',
    'database_editor': 'Database Editor',
    'audit_logs': 'Audit Logs',
    'reports': 'Reports Generator',
    'profile': 'User Profile',
    'api_console': 'API Console'
}

# Permission Matrix (role -> resource -> allowed actions)
PERMISSIONS = {
    'system_admin': {
        '*': ['read', 'write', 'delete', 'manage', 'grant']
    },
    'org_admin': {
        'user_management': ['read', 'write'],
        'role_management': ['read'],
        'database_viewer': ['read'],
        'audit_logs': ['read', 'write'],
        'reports': ['read', 'write'],
        'profile': ['read', 'write'],
        'dashboard': ['read']
    },
    'department_manager': {
        'user_management': ['read'],
        'reports': ['read', 'write'],
        'profile': ['read', 'write'],
        'dashboard': ['read']
    },
    'senior_developer': {
        'database_viewer': ['read', 'write'],
        'database_editor': ['read', 'write'],
        'api_console': ['read', 'write'],
        'reports': ['read'],
        'profile': ['read', 'write'],
        'dashboard': ['read']
    },
    'developer': {
        'database_viewer': ['read'],
        'database_editor': ['read'],
        'api_console': ['read'],
        'reports': ['read'],
        'profile': ['read', 'write'],
        'dashboard': ['read']
    },
    'security_auditor': {
        'audit_logs': ['read'],
        'user_management': ['read'],
        'role_management': ['read'],
        'profile': ['read'],
        'dashboard': ['read']
    },
    'user': {
        'dashboard': ['read'],
        'profile': ['read', 'write']
    }
}

# JIT Permissions (temporary elevated access)
JIT_PERMISSIONS = {
    'database_admin': ['database_viewer', 'database_editor'],
    'database_writer': ['database_viewer', 'database_editor'],
    'database_reader': ['database_viewer'],
    'backup_admin': ['database_viewer']
}

# Context processor
@app.context_processor
def inject_config():
    return dict(
        EMAIL_CONFIG=EMAIL_CONFIG,
        ORGANIZATIONAL_ROLES=ORGANIZATIONAL_ROLES,
        RESOURCE_ROLES=RESOURCE_ROLES,
        RESOURCES=RESOURCES,
        JIT_PERMISSIONS=JIT_PERMISSIONS,
        PERMISSIONS=PERMISSIONS
    )

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

class RBACSystem:
    """Role-Based Access Control System"""
    
    @staticmethod
    def check_permission(user_role, resource, action):
        """Check if user has permission for action on resource"""
        if user_role not in PERMISSIONS:
            return False
        
        # Check if user has JIT permission for this resource and action
        if RBACSystem.has_jit_permission(resource, action):
            return True
        
        # Check specific resource permissions
        if resource in PERMISSIONS[user_role]:
            if action in PERMISSIONS[user_role][resource]:
                return True
        
        # Check wildcard permissions
        if '*' in PERMISSIONS[user_role]:
            if action in PERMISSIONS[user_role]['*']:
                return True
        
        return False
    
    @staticmethod
    def has_jit_permission(resource, action=None):
        """Check if current user has JIT permission for resource and action"""
        if 'user_id' not in session:
            return False
        
        user_id = session['user_id']
        
        # Check database for active JIT permissions
        jit_permissions = db.get_active_jit_permissions(user_id)
        
        for perm in jit_permissions:
            perm_type = perm['permission_type']
            if perm_type in JIT_PERMISSIONS:
                if resource in JIT_PERMISSIONS[perm_type]:
                    # Check if the action is allowed by this JIT permission
                    if action:
                        # Get the permissions for this resource role
                        if perm_type in RESOURCE_ROLES:
                            resource_permissions = RESOURCE_ROLES[perm_type]['permissions']
                            if action in resource_permissions:
                                return True
                    else:
                        return True
        
        return False
    
    @staticmethod
    def can_manage_users(user_role):
        """Check if user can manage other users"""
        return user_role in ['system_admin', 'org_admin']
    
    @staticmethod
    def can_assign_roles(user_role, target_role):
        """Check if user can assign a specific role"""
        if user_role not in ORGANIZATIONAL_ROLES or target_role not in ORGANIZATIONAL_ROLES:
            return False
        
        # Users can only assign roles at or below their own level
        user_level = ORGANIZATIONAL_ROLES[user_role]['level']
        target_level = ORGANIZATIONAL_ROLES[target_role]['level']
        
        return user_level >= target_level and user_role != 'user'
    
    @staticmethod
    def can_delete_user(current_user_role, target_user_role, current_user_id, target_user_id):
        """Check if user can delete another user"""
        # Users cannot delete themselves
        if current_user_id == target_user_id:
            return False
        
        # Only system_admin can delete other admins
        if target_user_role in ['system_admin', 'org_admin']:
            return current_user_role == 'system_admin'
        
        # Check if user has permission to manage users
        return RBACSystem.can_manage_users(current_user_role)
    
    @staticmethod
    def get_role_hierarchy():
        """Get role hierarchy sorted by level"""
        return sorted(ORGANIZATIONAL_ROLES.items(), key=lambda x: x[1]['level'], reverse=True)

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
        # Assign system_admin role to admin
        db.assign_user_role(admin_id, 'system_admin', admin_id)
        print(f"Admin user created: {ADMIN_CONFIG['admin_username']} / AdminPass123! (Role: system_admin)")
    else:
        print(f"Admin user already exists")

# Authentication middleware with RBAC
@app.before_request
def check_auth():
    """Authentication and authorization middleware"""
    public_routes = ['login', 'register', 'verify_email', 'verify_login', 'static']
    
    if request.endpoint in public_routes:
        return
    
    # Check if user is authenticated
    session_token = request.cookies.get('session_token')
    if session_token:
        session_data = db.validate_session(session_token)
        if session_data:
            session['user_id'] = session_data['user_id']
            session['username'] = session_data['username']
            session['role'] = session_data.get('role', 'user')
            session['is_admin'] = (session['role'] == 'system_admin')
            return
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

# Authorization decorator
def require_permission(resource, action):
    """Decorator to check permissions"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                flash('Access denied. Please login.', 'error')
                return redirect(url_for('login'))
            
            if not RBACSystem.check_permission(session['role'], resource, action):
                flash(f'Access denied. You need {action} permission on {resource}.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def require_role(required_role):
    """Decorator to check for specific role"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                flash('Access denied. Please login.', 'error')
                return redirect(url_for('login'))
            
            if session['role'] != required_role:
                flash(f'Access denied. {required_role} role required.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Add RBACSystem to context processor
@app.context_processor
def inject_rbac():
    return dict(RBACSystem=RBACSystem)

@app.route('/')
def index():
    return redirect(url_for('login'))

# Registration and Login routes
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
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
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
            
            # Clear pending login session
            session.pop('pending_login_user_id', None)
            
            # Set user session
            session['user_id'] = pending_user_id
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            session['is_admin'] = (user.get('role') == 'system_admin')
            
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
@require_permission('dashboard', 'read')
def dashboard():
    """Main dashboard with RBAC information"""
    user = db.get_user_by_id(session['user_id'])
    
    # Get user's active JIT permissions
    active_jit_permissions = db.get_active_jit_permissions(session['user_id'])
    
    # Get user's role information
    role_info = ORGANIZATIONAL_ROLES.get(session['role'], ORGANIZATIONAL_ROLES['user'])
    
    # Get available resources based on permissions
    available_resources = []
    for resource, actions in PERMISSIONS.get(session['role'], {}).items():
        if resource != '*' and 'read' in actions:
            available_resources.append(resource)
    
    # Add resources from JIT permissions
    for jit_perm in active_jit_permissions:
        perm_type = jit_perm['permission_type']
        if perm_type in JIT_PERMISSIONS:
            for resource in JIT_PERMISSIONS[perm_type]:
                if resource not in available_resources:
                    available_resources.append(resource)
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         email=user['email'],
                         role=session['role'],
                         role_info=role_info,
                         active_jit_permissions=active_jit_permissions,
                         available_resources=available_resources,
                         last_login=user['last_login'] or "First login")

@app.route('/admin/db-viewer')
@require_permission('database_viewer', 'read')
def db_viewer():
    """Database viewer - requires database_viewer:read permission"""
    try:
        # Check if user has either regular permission or JIT permission
        if not RBACSystem.check_permission(session['role'], 'database_viewer', 'read') and not RBACSystem.has_jit_permission('database_viewer', 'read'):
            flash('Access denied. You need read permission on database_viewer.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all users
        users = db.execute_query("""
            SELECT id, username, email, role, password_hash, is_verified,
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
        
        # Get active JIT permissions
        active_jit_permissions = db.execute_query("""
            SELECT jp.*, u.username,
                   datetime(jp.granted_at) as granted_at_formatted,
                   datetime(jp.expires_at) as expires_at_formatted
            FROM jit_permissions jp
            LEFT JOIN users u ON jp.user_id = u.id
            WHERE jp.status = 'approved' 
            AND datetime(jp.expires_at) > datetime('now')
            ORDER BY jp.expires_at DESC
        """, fetchall=True) or []
        
        # Clean up expired data automatically
        db.cleanup_expired_data()
        
        return render_template('db_viewer.html', 
                             users=users or [],
                             verification_codes=verification_codes or [], 
                             sessions=sessions or [],
                             active_jit_permissions=active_jit_permissions)
    
    except Exception as e:
        flash(f'Error accessing database: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/user-management')
@require_permission('user_management', 'read')
def user_management():
    """User management page - requires user_management:read permission"""
    users = db.get_all_users_with_roles()
    
    return render_template('user_management.html', 
                         users=users or [],
                         roles=ORGANIZATIONAL_ROLES)

@app.route('/admin/assign-role', methods=['POST'])
@require_permission('user_management', 'write')
def assign_role():
    """Assign role to user - requires user_management:write permission"""
    username = request.form.get('username')
    role = request.form.get('role')
    
    if not username or not role:
        flash('Username and role are required', 'error')
        return redirect(url_for('user_management'))
    
    if role not in ORGANIZATIONAL_ROLES:
        flash('Invalid role', 'error')
        return redirect(url_for('user_management'))
    
    user = db.get_user_by_username(username)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('user_management'))
    
    # Check if current user can assign this role
    if not RBACSystem.can_assign_roles(session['role'], role):
        flash(f'You cannot assign the {role} role. You can only assign roles at or below your level.', 'error')
        return redirect(url_for('user_management'))
    
    db.assign_user_role(user['id'], role, session['user_id'])
    
    # Log the action
    db.log_action(
        session['user_id'],
        'assign_role',
        f"Assigned role '{role}' to user '{username}'",
        'user_management'
    )
    
    flash(f'Role {ORGANIZATIONAL_ROLES[role]["name"]} assigned to {username}', 'success')
    return redirect(url_for('user_management'))

@app.route('/jit/request-permission', methods=['GET', 'POST'])
@require_permission('dashboard', 'read')
def request_jit_permission():
    """Request JIT permission page"""
    if request.method == 'POST':
        permission_type = request.form.get('permission_type')
        duration = int(request.form.get('duration', 60))
        reason = request.form.get('reason', 'Temporary access needed')
        
        if not permission_type:
            flash('Permission type is required', 'error')
            return redirect(url_for('request_jit_permission'))
        
        # Validate permission type
        if permission_type not in RESOURCE_ROLES:
            flash('Invalid permission type', 'error')
            return redirect(url_for('request_jit_permission'))
        
        # Request JIT permission (needs admin approval)
        success = db.request_jit_permission(
            session['user_id'],
            permission_type,
            duration,
            reason
        )
        
        if success:
            flash(f'JIT permission "{RESOURCE_ROLES[permission_type]["name"]}" requested. Awaiting admin approval.', 'success')
            
            # Log the action
            db.log_action(
                session['user_id'],
                'jit_permission_request',
                f"Requested JIT permission '{permission_type}' for {duration} minutes: {reason}",
                'jit_system'
            )
        else:
            flash('Failed to request JIT permission', 'error')
        
        return redirect(url_for('dashboard'))
    
    # GET request - show available JIT permissions
    pending_requests = db.execute_query("""
        SELECT * FROM jit_permissions 
        WHERE user_id = ? AND status = 'pending'
    """, (session['user_id'],), fetchall=True) or []
    
    return render_template('jit_request.html',
                         pending_requests=pending_requests)

@app.route('/admin/jit-requests')
@require_permission('user_management', 'read')
def jit_requests():
    """View pending JIT requests (admin only)"""
    if not RBACSystem.can_manage_users(session['role']):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    pending_requests = db.get_pending_jit_requests()
    
    return render_template('jit_requests.html',
                         pending_requests=pending_requests,
                         RESOURCE_ROLES=RESOURCE_ROLES)

@app.route('/admin/jit-approve/<int:permission_id>', methods=['POST'])
@require_permission('user_management', 'write')
def approve_jit_request(permission_id):
    """Approve a JIT request"""
    if not RBACSystem.can_manage_users(session['role']):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    duration = int(request.form.get('duration', 60))
    
    success = db.approve_jit_permission(permission_id, session['user_id'], duration)
    
    if success:
        # Get request info for logging
        request_info = db.execute_query(
            "SELECT jp.*, u.username FROM jit_permissions jp JOIN users u ON jp.user_id = u.id WHERE jp.id = ?",
            (permission_id,), fetchone=True
        )
        
        if request_info:
            flash(f'JIT request approved for {request_info["username"]}', 'success')
            
            db.log_action(
                session['user_id'],
                'jit_permission_approve',
                f"Approved JIT permission '{request_info['permission_type']}' for user '{request_info['username']}'",
                'jit_system'
            )
    else:
        flash('Failed to approve JIT request', 'error')
    
    return redirect(url_for('jit_requests'))

@app.route('/admin/jit-deny/<int:permission_id>', methods=['POST'])
@require_permission('user_management', 'write')
def deny_jit_request(permission_id):
    """Deny a JIT request"""
    if not RBACSystem.can_manage_users(session['role']):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    success = db.deny_jit_permission(permission_id, session['user_id'])
    
    if success:
        # Get request info for logging
        request_info = db.execute_query(
            "SELECT jp.*, u.username FROM jit_permissions jp JOIN users u ON jp.user_id = u.id WHERE jp.id = ?",
            (permission_id,), fetchone=True
        )
        
        if request_info:
            flash(f'JIT request denied for {request_info["username"]}', 'success')
            
            db.log_action(
                session['user_id'],
                'jit_permission_deny',
                f"Denied JIT permission '{request_info['permission_type']}' for user '{request_info['username']}'",
                'jit_system'
            )
    else:
        flash('Failed to deny JIT request', 'error')
    
    return redirect(url_for('jit_requests'))

@app.route('/admin/audit/logs')
@require_permission('audit_logs', 'read')
def audit_logs():
    """View audit logs - requires audit_logs:read permission"""
    search = request.args.get('search', '')
    action_type = request.args.get('action_type', '')
    
    query = """
        SELECT al.*, u.username,
               datetime(al.timestamp) as timestamp_formatted
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE 1=1
    """
    params = []
    
    if search:
        query += " AND (al.description LIKE ? OR al.resource LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%'])
    
    if action_type:
        query += " AND al.action_type = ?"
        params.append(action_type)
    
    query += " ORDER BY al.timestamp DESC LIMIT 100"
    
    logs = db.execute_query(query, params, fetchall=True) or []
    
    return render_template('audit_logs.html', logs=logs)

@app.route('/profile')
@require_permission('profile', 'read')
def profile():
    """User profile page"""
    user = db.get_user_by_id(session['user_id'])
    
    # Get user's role assignments history
    role_history = db.execute_query("""
        SELECT ur.role_id, ur.assigned_at, u2.username as assigned_by,
               datetime(ur.assigned_at) as assigned_at_formatted
        FROM user_roles ur
        LEFT JOIN users u2 ON ur.assigned_by = u2.id
        WHERE ur.user_id = ?
        ORDER BY ur.assigned_at DESC
    """, (session['user_id'],), fetchall=True) or []
    
    # Get JIT permission history
    jit_history = db.execute_query("""
        SELECT permission_type, granted_at, expires_at, reason, is_active,
               datetime(granted_at) as granted_at_formatted,
               datetime(expires_at) as expires_at_formatted
        FROM jit_permissions
        WHERE user_id = ?
        ORDER BY granted_at DESC
        LIMIT 20
    """, (session['user_id'],), fetchall=True) or []
    
    return render_template('profile.html',
                         user=user,
                         role_history=role_history,
                         jit_history=jit_history,
                         role_info=ORGANIZATIONAL_ROLES.get(session['role'], {}))

@app.route('/resources')
@require_permission('dashboard', 'read')
def resources():
    """List all resources user can access"""
    user_role = session['role']
    available_resources = []
    
    # Get regular permissions
    for resource, actions in PERMISSIONS.get(user_role, {}).items():
        if resource != '*' and 'read' in actions:
            available_resources.append({
                'name': resource,
                'title': RESOURCES.get(resource, resource.replace('_', ' ').title()),
                'description': RESOURCES.get(resource, 'No description available'),
                'access_type': 'Regular Role Permission',
                'actions': actions,
                'role': user_role
            })
    
    # Get JIT permissions
    jit_permissions = db.get_active_jit_permissions(session['user_id'])
    for jit_perm in jit_permissions:
        perm_type = jit_perm['permission_type']
        if perm_type in JIT_PERMISSIONS:
            for resource in JIT_PERMISSIONS[perm_type]:
                # Check if already added
                if not any(r['name'] == resource for r in available_resources):
                    available_resources.append({
                        'name': resource,
                        'title': RESOURCES.get(resource, resource.replace('_', ' ').title()),
                        'description': RESOURCES.get(resource, 'No description available'),
                        'access_type': f'JIT: {RESOURCE_ROLES[perm_type]["name"]}',
                        'actions': RESOURCE_ROLES[perm_type]['permissions'],
                        'expires_at': jit_perm['expires_at'],
                        'role': perm_type
                    })
    
    return render_template('resources.html',
                         resources=available_resources,
                         user_role=user_role)

@app.route('/admin/role-management')
@require_permission('role_management', 'read')
def role_management():
    """Role management page - shows all roles and hierarchy"""
    role_hierarchy = RBACSystem.get_role_hierarchy()
    
    return render_template('role_management.html',
                         role_hierarchy=role_hierarchy)

@app.route('/admin/update-user', methods=['POST'])
@require_permission('database_viewer', 'write')
def update_user():
    """Update user information"""
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    verified = request.form.get('verified') == '1'
    password = request.form.get('password')
    
    try:
        # Update basic info
        db.execute_query(
            "UPDATE users SET username = ?, email = ?, role = ?, is_verified = ? WHERE id = ?",
            (username, email, role, verified, user_id)
        )
        
        # Update password if provided
        if password:
            password_hash = generate_password_hash(password)
            db.execute_query(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id)
            )
        
        db.log_action(
            session['user_id'],
            'update_user',
            f"Updated user {username} (ID: {user_id})",
            'database_viewer'
        )
        
        flash(f'User {username} updated successfully', 'success')
        return redirect(url_for('db_viewer'))
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'error')
        return redirect(url_for('db_viewer'))

@app.route('/admin/create-user', methods=['POST'])
@require_permission('database_viewer', 'write')
def create_user():
    """Create new user"""
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    verified = request.form.get('verified') == '1'
    password = request.form.get('password', 'DefaultPass123!')
    
    try:
        # Check if user exists
        if db.user_exists(username, email):
            flash('Username or email already exists', 'error')
            return redirect(url_for('db_viewer'))
        
        # Create user
        password_hash = generate_password_hash(password)
        db.execute_query(
            "INSERT INTO users (username, email, password_hash, role, is_verified) VALUES (?, ?, ?, ?, ?)",
            (username, email, password_hash, role, verified)
        )
        
        db.log_action(
            session['user_id'],
            'create_user',
            f"Created new user {username} with role {role}",
            'database_viewer'
        )
        
        flash(f'User {username} created successfully', 'success')
        return redirect(url_for('db_viewer'))
    except Exception as e:
        flash(f'Error creating user: {str(e)}', 'error')
        return redirect(url_for('db_viewer'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@require_permission('database_viewer', 'write')
def delete_user(user_id):
    """Delete a user"""
    if user_id == session['user_id']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('db_viewer'))
    
    try:
        user = db.get_user_by_id(user_id)
        if user:
            # Delete user and related data
            db.execute_query("DELETE FROM users WHERE id = ?", (user_id,))
            db.execute_query("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            db.execute_query("DELETE FROM verification_codes WHERE user_id = ?", (user_id,))
            db.execute_query("DELETE FROM jit_permissions WHERE user_id = ?", (user_id,))
            db.execute_query("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
            
            db.log_action(
                session['user_id'],
                'delete_user',
                f"Deleted user {user['username']} (ID: {user_id})",
                'database_viewer'
            )
            
            flash(f'User {user["username"]} deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('db_viewer'))

@app.route('/admin/delete-session/<int:session_id>', methods=['POST'])
@require_permission('database_viewer', 'write')
def delete_session_route(session_id):
    """Delete a session"""
    try:
        db.execute_query("DELETE FROM sessions WHERE id = ?", (session_id,))
        
        db.log_action(
            session['user_id'],
            'delete_session',
            f"Deleted session {session_id}",
            'database_viewer'
        )
        
        flash('Session revoked successfully', 'success')
    except Exception as e:
        flash(f'Error deleting session: {str(e)}', 'error')
    
    return redirect(url_for('db_viewer'))

@app.route('/admin/clear-sessions', methods=['POST'])
@require_permission('database_viewer', 'write')
def clear_sessions():
    """Clear all sessions"""
    try:
        db.execute_query("DELETE FROM sessions WHERE user_id != ?", (session['user_id'],))
        
        db.log_action(
            session['user_id'],
            'clear_sessions',
            "Cleared all user sessions",
            'database_viewer'
        )
        
        flash('All sessions cleared successfully', 'success')
    except Exception as e:
        flash(f'Error clearing sessions: {str(e)}', 'error')
    
    return redirect(url_for('db_viewer'))

@app.route('/admin/cleanup', methods=['POST'])
@require_permission('database_viewer', 'write')
def cleanup_database():
    """Clean up expired data"""
    try:
        db.cleanup_expired_data()
        
        db.log_action(
            session['user_id'],
            'database_cleanup',
            "Performed database cleanup",
            'database_viewer'
        )
        
        flash('Database cleanup completed successfully', 'success')
    except Exception as e:
        flash(f'Error during cleanup: {str(e)}', 'error')
    
    return redirect(url_for('db_viewer'))

@app.route('/logout')
def logout():
    # Clear session token cookie if exists
    session_token = request.cookies.get('session_token')
    
    if session_token:
        db.delete_session(session_token)
    
    # Clear all session data
    session.clear()
    
    # Create response and clear cookie
    response = make_response(redirect(url_for('login')))
    response.set_cookie('session_token', '', expires=0)
    response.set_cookie('session', '', expires=0)
    
    flash('Logout successful!', 'success')
    return response

# Create admin user when app starts
with app.app_context():
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)