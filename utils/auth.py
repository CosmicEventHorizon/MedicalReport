import bcrypt
import jwt
from datetime import datetime, timezone, timedelta 
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from dotenv import load_dotenv
import os

load_dotenv('config.env')
SECRET_KEY = os.getenv('JWT_SECRET')

def get_user(username):
    conn = sqlite3.connect('instance/users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(username, password, email, first_name, last_name, dob):
    conn = sqlite3.connect('instance/users.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password, email, first_name, last_name, dob) VALUES (?, ?, ?, ?, ?, ?)",
        (username, password, email, first_name, last_name, dob)
    )
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(stored_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_password)

def generate_jwt(username):
    print(SECRET_KEY)
    token = jwt.encode({
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')
    return token

def get_authorization_info(token):
    if not token:
        print("No token, not authorized")
        return False, None  

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        exp_time = datetime.fromtimestamp(decoded['exp'], timezone.utc)
        if exp_time < datetime.now(timezone.utc):
            print("Token expired, not authorized")
            return False, None   
        return True, decoded['username']  
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return False, None  
    except jwt.InvalidTokenError:
        print("Invalid token")
        return False, None  