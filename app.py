from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# API Ninjas API Key - Get free key at https://api-ninjas.com/
API_NINJAS_KEY = '+PfEP0F78yN7Bv7RO0uw+A==myZNDLRXn8q1cxgk'

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create tables
with app.app_context():
    db.create_all()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# API Ninjas helper functions
def get_quote():
    try:
        response = requests.get(
            'https://api.api-ninjas.com/v1/quotes?category=happiness',
            headers={'X-Api-Key': API_NINJAS_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else {'quote': 'No quote available', 'author': 'Unknown'}
    except:
        pass
    return {'quote': 'Unable to fetch quote', 'author': 'Unknown'}

def get_trivia():
    try:
        response = requests.get(
            'https://api.api-ninjas.com/v1/trivia',
            headers={'X-Api-Key': API_NINJAS_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else {'question': 'No trivia available', 'answer': ''}
    except:
        pass
    return {'question': 'Unable to fetch trivia', 'answer': ''}

def get_riddle():
    try:
        response = requests.get(
            'https://api.api-ninjas.com/v1/riddles',
            headers={'X-Api-Key': API_NINJAS_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else {'title': 'No riddle available', 'question': '', 'answer': ''}
    except:
        pass
    return {'title': 'Unable to fetch riddle', 'question': '', 'answer': ''}

def get_joke():
    try:
        response = requests.get(
            'https://api.api-ninjas.com/v1/jokes',
            headers={'X-Api-Key': API_NINJAS_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else {'joke': 'No joke available'}
    except:
        pass
    return {'joke': 'Unable to fetch joke'}

def get_dadjoke():
    try:
        response = requests.get(
            'https://api.api-ninjas.com/v1/dadjokes',
            headers={'X-Api-Key': API_NINJAS_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else {'joke': 'No dad joke available'}
    except:
        pass
    return {'joke': 'Unable to fetch dad joke'}

@app.route('/')
def index():
    quote = get_quote()
    trivia = get_trivia()
    riddle = get_riddle()
    joke = get_joke()
    dadjoke = get_dadjoke()
    
    return render_template('index.html', 
                         quote=quote,
                         trivia=trivia,
                         riddle=riddle,
                         joke=joke,
                         dadjoke=dadjoke)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)