from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
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
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ticket_price = db.Column(db.Float, nullable=False)
    photo_url = db.Column(db.String(400))  # Add a photo_url field (adjust length as needed)
    event_date = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"Event(id={self.id}, title={self.title}, ticket_price={self.ticket_price}, photo_url={self.photo_url})"
@app.route('/events', methods=['GET'])
def get_events():
    events = Event.query.all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'ticket_price': event.ticket_price,
        'photo_url': event.photo_url,
        'event_date': event.event_date.strftime('%Y-%m-%d %H:%M:%S')
    } for event in events]), 200

@app.route('/events', methods=['POST'])
@jwt_required()
def create_event():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    title = data.get('title')
    description = data.get('description')
    ticket_price = data.get('ticket_price')
    photo_url = data.get('photo_url')  # Fetch photo_url from request data
    event_date_str = data.get('event_date')

    if not title or not description or not ticket_price or not event_date_str:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        event_date = datetime.datetime.strptime(event_date_str, '%Y-%m-%dT%H:%M:%S.%fZ')  # Adjust format as per your frontend's datetime format

        new_event = Event(
            title=title,
            description=description,
            ticket_price=ticket_price,
            photo_url=photo_url,
            event_date=event_date
        )

        db.session.add(new_event)
        db.session.commit()
        return jsonify({'message': 'Event created successfully'}), 201
    except ValueError as e:
        return jsonify({'error': 'Invalid date format, please use YYYY-MM-DDTHH:MM:SSZ'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create event: {str(e)}'}), 500

@app.route('/events/<int:event_id>', methods=['DELETE'])
@jwt_required()  # Protect event deletion route with JWT
def delete_event(event_id):
    event = Event.query.get(event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404

    try:
        db.session.delete(event)
        db.session.commit()
        return jsonify({'message': 'Event deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete event: {str(e)}'}), 500

@app.route('/events/<int:event_id>', methods=['PUT'])
@jwt_required()
def update_event(event_id):
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    title = data.get('title')
    description = data.get('description')
    ticket_price = data.get('ticket_price')
    photo_url = data.get('photo_url')  # Fetch photo_url from request data
    event_date_str = data.get('event_date')

    if not title or not description or not ticket_price or not event_date_str:
        return jsonify({'error': 'Missing required fields'}), 400

    event = Event.query.get(event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404

    try:
        event_date = datetime.datetime.strptime(event_date_str, '%Y-%m-%dT%H:%M:%S.%fZ')  # Adjust format as per your frontend's datetime format

        event.title = title
        event.description = description
        event.ticket_price = ticket_price
        event.photo_url = photo_url
        event.event_date = event_date

        db.session.commit()
        return jsonify({'message': 'Event updated successfully'}), 200
    except ValueError as e:
        return jsonify({'error': 'Invalid date format, please use YYYY-MM-DDTHH:MM:SSZ'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update event: {str(e)}'}), 500
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