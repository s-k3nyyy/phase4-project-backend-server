from models import db, User
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
# from auth import jwt, auth_bp, bcrypt
# from flask_jwt_extended import jwt_required, current_user
from flask_bcrypt import Bcrypt
from flask_cors import CORS


app = Flask(__name__)
CORS(app)  # Enable CORS for development, restrict as needed

# app.config.from_pyfile('config.py')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

SECRET_KEY = 'your_secret_key_here'

db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)



# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        phone_number=data['phoneNumber']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username_or_email = data.get('username_or_email')
    password = data.get('password')

    if not username_or_email or not password:
        return jsonify({'error': 'Missing username/email or password'}), 400

    # Check if username_or_email is an email
    user = User.query.filter_by(email=username_or_email).first()

    # If not found by email, check by username
    if not user:
        user = User.query.filter_by(username=username_or_email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    return jsonify({'message': 'Login successful'}), 200

if __name__ == '__main__':
    app.run(debug=True)