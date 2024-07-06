from flask import Flask, Blueprint, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import secrets

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow() + timedelta(hours=1))

    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))

# Blueprints
auth_bp = Blueprint('auth_bp', __name__)
CORS(auth_bp)

def mask_email(email):
    parts = email.split('@')
    if len(parts) != 2:
        return email
    return f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}@{parts[1]}"

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify(message='Username, email, and password are required'), 400

    if User.query.filter_by(username=username).first():
        return jsonify(message='Username already exists'), 400

    if User.query.filter_by(email=email).first():
        return jsonify(message='Email already exists'), 400

    user = User(username=username, email=email)
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
    if not user or not user.check_password(password):
        return jsonify(message='Invalid username or password'), 401

    token = 'your_generated_token'

    return jsonify(message='Logged in successfully', token=token), 200

@auth_bp.route('/api/get_masked_email', methods=['POST'])
def get_masked_email():
    data = request.get_json()
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    masked_email = mask_email(user.email)
    return jsonify({'masked_email': masked_email}), 200

@auth_bp.route('/api/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    token = secrets.token_urlsafe(30)
    reset_token = ResetToken(token=token, user_id=user.id)
    db.session.add(reset_token)
    db.session.commit()

    # Example: send_reset_token(user.email, token)

    return jsonify({'message': 'Reset token sent', 'token': token}), 200

@auth_bp.route('/api/reset_password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('password')

    reset_token = ResetToken.query.filter_by(token=token).first()
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        return jsonify({'message': 'Invalid or expired token'}), 400

    user = User.query.get(reset_token.user_id)
    user.set_password(new_password)
    db.session.delete(reset_token)
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200

app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(debug=True)
