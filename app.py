from datetime import datetime, timedelta
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_cors import CORS
from flask_restful import Api, Resource, reqparse
from flask_migrate import Migrate
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
api = Api(app)
migrate = Migrate(app, db)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ticket_price = db.Column(db.Float, nullable=False)
    photo_url = db.Column(db.String(200))
    event_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Event {self.title}>'

    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'ticket_price': self.ticket_price,
            'photo_url': self.photo_url,
            'event_date': self.event_date.isoformat(),
            'created_at': self.created_at.isoformat()
        }

# Resources
class UserRegister(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('phone_number', type=str, required=True, help='Phone number is required')
        args = parser.parse_args()

        username = args['username']
        email = args['email']
        password = args['password']
        phone_number = args['phone_number']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'Username already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password, phone_number=phone_number)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201

class AdminRegister(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username = args['username']
        password = args['password']

        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            return {'message': 'Admin already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_admin = Admin(username=username, password_hash=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

        return {'message': 'Admin registered successfully'}, 201
class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username_or_email', type=str, required=True, help='Username or email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username_or_email = args['username_or_email']
        password = args['password']

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
            refresh_token = create_refresh_token(identity=user.id)
            return {'access_token': access_token, 'efresh_token': refresh_token}, 200
        return {'message': 'Invalid credentials'}, 401

class AdminLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username = args['username']
        password = args['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.password_hash, password):
            access_token = create_access_token(identity=admin.id, expires_delta=timedelta(minutes=30))
            refresh_token = create_refresh_token(identity=admin.id)
            return {'access_token': access_token, 'efresh_token': refresh_token}, 200
        return {'message': 'Invalid credentials'}, 401

class TokenResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        user_id = get_jwt_identity()
        access_token = create_access_token(identity=user_id, expires_delta=timedelta(minutes=30))
        refresh_token = create_refresh_token(identity=user_id)
        return {'access_token': access_token, 'efresh_token': refresh_token}, 200

    @jwt_required(refresh=False)
    def get(self):
        user_id = get_jwt_identity()
        return {'access_token': create_access_token(identity=user_id, expires_delta=timedelta(minutes=30))}, 200

class EventList(Resource):
    def get(self):
        events = Event.query.all()
        return [event.serialize() for event in events], 200

class EventCreate(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str, required=True, help='Title is required')
        parser.add_argument('description', type=str, required=True, help='Description is required')
        parser.add_argument('ticket_price', type=float, required=True, help='Ticket price is required')
        parser.add_argument('photo_url', type=str, required=True, help='Photo URL is required')
        parser.add_argument('event_date', type=str, required=True, help='Event date is required')
        args = parser.parse_args()

        title = args['title']
        description = args['description']
        ticket_price = args['ticket_price']
        photo_url = args['photo_url']
        event_date = datetime.fromisoformat(args['event_date'])

        new_event = Event(title=title, description=description, ticket_price=ticket_price, photo_url=photo_url, event_date=event_date)
        db.session.add(new_event)
        db.session.commit()

        return {'message': 'Event created successfully'}, 201
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# API routes
api.add_resource(UserRegister, '/register')
api.add_resource(AdminRegister, '/admin/register')
api.add_resource(UserLogin, '/login')
api.add_resource(AdminLogin, '/admin/login')
api.add_resource(TokenResource, '/token')
api.add_resource(EventList, '/events')
api.add_resource(EventCreate, '/events/create')

if __name__ == '__main__':
    app.run(debug=True)