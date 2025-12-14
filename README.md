# Information Security Lab 3 – Role-Based Access Control (RBAC) with JIT Access

A secure Flask web application demonstrating **Role-Based Access Control (RBAC)** combined with **Just-In-Time (JIT) privileged access**, designed to enforce the principle of least privilege and provide temporary elevated access when required.

This project extends standard authentication mechanisms with fine-grained authorization, administrative oversight, and full auditing of system actions.

## Features

- **Role-Based Access Control (RBAC)** with hierarchical organizational roles  
- **7 predefined system roles** with clear separation of privileges  
- **Permission matrix** defining allowed actions per role and resource  
- **Decorator-based authorization** for route-level access control  
- **Just-In-Time (JIT) access system** for temporary elevated permissions  
- **Admin approval workflow** for JIT permission requests  
- **Automatic expiration** of temporary permissions  
- **Secure user authentication** with hashed passwords (PBKDF2)  
- **Two-factor authentication (2FA)** using verification codes  
- **Secure session management** with HTTP-only cookies  
- **Audit logging system** for full traceability of user actions  

## System Roles

- **System Administrator** – Full system access  
- **Organizational Administrator** – User and role management  
- **Department Manager** – Department-level reporting access  
- **Senior Developer** – Extended development and database access  
- **Developer** – Read-only access to development resources  
- **Security Auditor** – Read-only access to audit logs  
- **User** – Basic profile and dashboard access  

## Just-In-Time (JIT) Roles

- **Database Administrator** – Full database access  
- **Database Writer** – Read and write database access  
- **Database Reader** – Read-only database access  
- **Backup Administrator** – Backup management access  

## Admin Access

Default administrator credentials for testing:

- **Username:** `admin`  
- **Email:** `admin@auth-system.com`  
- **Password:** `AdminPass123!` 
  
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

### ! This project was developed as part of the Information Security laboratory exercises and is is intended for educational and demonstrational purposes only.
