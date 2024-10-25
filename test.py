from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import re
import json
import base64
import random
import string
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Constants and configurations
PASSWORD_FILE = "passwords.json"
MASTER_PASSWORD_FILE = "master_password.json"

# Utility functions
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

def validate_password(password: str) -> bool:
    if (len(password) < 8 or 
        not re.search("[a-z]", password) or 
        not re.search("[A-Z]", password) or 
        not re.search("[0-9]", password) or 
        not re.search("[@#$%^&+=]", password)):
        return False
    return True

def load_passwords() -> dict:
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_passwords(passwords: dict):
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(passwords, file, indent=4)

def generate_random_password(length: int = 12) -> str:
    characters = string.ascii_letters + string.digits + "@#$%^&+="
    return ''.join(random.choice(characters) for _ in range(length))

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if os.path.exists(MASTER_PASSWORD_FILE):
        return redirect(url_for('login'))
    return redirect(url_for('setup'))

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if os.path.exists(MASTER_PASSWORD_FILE):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        master_password = request.form.get('master_password')
        if validate_password(master_password):
            with open(MASTER_PASSWORD_FILE, 'w') as file:
                json.dump({"master_password": master_password}, file)
            flash('Master password set successfully!', 'success')
            return redirect(url_for('login'))
        flash('Invalid password format!', 'error')
    
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        with open(MASTER_PASSWORD_FILE, 'r') as file:
            stored_password = json.load(file)["master_password"]
        
        if request.form.get('master_password') == stored_password:
            session['authenticated'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Incorrect master password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    passwords = load_passwords()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/store', methods=['GET', 'POST'])
@login_required
def store_password():
    if request.method == 'POST':
        service = request.form.get('service')
        password = request.form.get('password')
        
        passwords = load_passwords()
        passwords[service] = password
        save_passwords(passwords)
        
        flash(f'Password for {service} stored successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('store.html')

@app.route('/delete/<service>')
@login_required
def delete_service(service):
    passwords = load_passwords()
    if service in passwords:
        del passwords[service]
        save_passwords(passwords)
        flash(f'Service {service} deleted successfully!', 'success')
    else:
        flash(f'Service {service} not found!', 'error')
    return redirect(url_for('dashboard'))

@app.route('/generate')
@login_required
def generate_password():
    length = request.args.get('length', 12, type=int)
    if length < 8:
        length = 12
    password = generate_random_password(length)
    return {'password': password}

if __name__ == '__main__':
    app.run(debug=True)
