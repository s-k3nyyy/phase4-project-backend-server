from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import logging
import os
import secrets

app = Flask(__name__, instance_relative_config=True)
CORS(app)

instance_path = app.instance_path
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
app.config['SESSION_COOKIE_SECURE'] = True  # Ensures cookies are only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Ensures cookies are not accessible via JavaScript
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'user.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'd7b912c529c3fba6079a7252'  # Set a secure secret key for session management

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)  # Initialize Flask-Login

logging.basicConfig(level=logging.DEBUG)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all tables
with app.app_context():
    db.create_all()

# Endpoint for user registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    logging.debug(f'Registration data: {data}')
    
    # Check if the username or email already exists
    user = User.query.filter(db.or_(User.username == data['username'], User.email == data['email'])).first()
    if user:
        logging.debug('Account already exists')
        return jsonify({'message': 'Username or email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    logging.debug('User registered successfully')
    return jsonify({'message': 'User registered successfully'})

# Endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)  # Log in the user using Flask-Login
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/logout')
@login_required
def logout():
    logout_user()  # Log out the user using Flask-Login
    return jsonify({'message': 'Logged out successfully'})

# Endpoint for user logout
@app.route('/api/logout')
@login_required
def logout():
    logout_user()  # Log out the user using Flask-Login
    return jsonify({'message': 'Logged out successfully'})

# Endpoint for home page
@app.route('/')
@login_required
def home():
    return jsonify({'message': 'Welcome to the Flask API'})

if __name__ == '__main__':
    app.run(debug=True)
