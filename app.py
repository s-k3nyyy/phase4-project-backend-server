from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secure random key
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'  # Change this to a secure random key

# Initialize Flask extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Apply CORS to your Flask app
CORS(app)

# User and Admin Models
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20))

class Admin(db.Model):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Routes
@app.route('/register/user', methods=['POST'])
def register_user():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        phone_number=phone_number
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to register user: {str(e)}'}), 500

@app.route('/register/admin', methods=['POST'])
def register_admin():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_admin = Admin(
        username=username,
        email=email,
        password=hashed_password
    )

    try:
        db.session.add(new_admin)
        db.session.commit()
        return jsonify({'message': 'Admin registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to register admin: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username_or_email = data.get('username_or_email')
    password = data.get('password')

    if not username_or_email or not password:
        return jsonify({'error': 'Missing username/email or password'}), 400

    # Check if user exists in both 'username' and 'email' fields
    user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.username)
    return jsonify(access_token=access_token), 200

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    admin = Admin.query.filter_by(username=username).first()
    if not admin or not bcrypt.check_password_hash(admin.password, password):
        return jsonify({'error': 'Invalid admin credentials'}), 401

    access_token = create_access_token(identity=admin.username)
    return jsonify(access_token=access_token), 200

@app.route('/admin/dashboard', methods=['GET'])
@jwt_required()  # Protect admin dashboard route with JWT
def admin_dashboard():
    current_admin = get_jwt_identity()
    return jsonify({'message': f'Welcome to the Admin Dashboard, {current_admin}!'})

if __name__ == '__main__':
    app.run(debug=True)
