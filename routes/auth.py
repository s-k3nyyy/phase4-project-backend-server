from flask import Blueprint, request, jsonify
from extensions import db
from models import User

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify(message='Username and password are required'), 400

    if User.query.filter_by(username=username).first():
        return jsonify(message='Username already exists'), 400

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify(message='User registered successfully'), 201

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify(message='Invalid username or password'), 401

    # Generate token logic here (using JWT or similar)
    token = 'your_generated_token'  # Placeholder

    return jsonify(message='Logged in successfully', token=token), 200
