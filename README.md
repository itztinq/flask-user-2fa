# Information Security Lab 2 – Advanced Authentication System

A secure Flask web application demonstrating advanced user registration, two-factor authentication, and admin security features with comprehensive protection mechanisms.

### Features

- **User registration** with username, email, and secure password validation  
- **Email verification system** with 6-digit confirmation codes  
- **Two-factor authentication (2FA)** for enhanced login security  
- **Secure password hashing** using Werkzeug (PBKDF2)  
- **Session management** with HTTP-only cookies and expiration  
- **Admin dashboard** with database viewer and user management  
- **SQL injection protection** through parameterized queries  
- **CSRF protection** via SameSite cookie policies

### Admin Access

- Full database visibility
  
**Username:** `admin`  
**Email:** `admin@auth-system.com`  
**Password:** `AdminPass123!`  
  
### Setup 

1. Clone the repository:  
   `git clone https://github.com/itztinq/flask-user-2fa.git`

2. Open the folder in your preferred code editor (e.g., VS Code).

3. Create and activate a virtual environment:  
   - **Windows:** `python -m venv venv` → `venv\Scripts\activate`  
   - **Mac/Linux:** `python -m venv venv` → `source venv/bin/activate`

4. Install dependencies:  
   `pip install -r requirements.txt`

5. Run the application:  
   `python app.py`

6. Open your browser at `http://127.0.0.1:5000` and test the authentication system.
