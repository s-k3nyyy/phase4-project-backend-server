
from datetime import datetime, timedelta
import logging

from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_cors import CORS
from flask_restful import Api, Resource, reqparse
from flask_migrate import Migrate
from config import Config
import secrets

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'X-CSRF-TOKEN'
app.config['JWT_COOKIE_SECURE'] = True  # Ensure HTTPS
app.config['JWT_COOKIE_SAMESITE'] = 'None'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"*": {"origins": "https://s-k3nyyy.github.io/s-k3nyyy-phase4-project-frontend-client", "methods": ["GET", "POST", "PUT", "DELETE"]}})

api = Api(app)
migrate = Migrate(app, db)

# Setup logging
logging.basicConfig(level=logging.INFO)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    jwt_key = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    bookmarked_events = db.relationship('UserEvent', backref='user', lazy=True)
    def __repr__(self):
        return f'<User {self.username}>'

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ticket_price = db.Column(db.Float, nullable=False)
    photo_url = db.Column(db.String(255))  # Optional field for event photo URL
    event_date = db.Column(db.DateTime, nullable=False)
    tickets_remaining = db.Column(db.Integer, default=0)
    jwt_required = db.Column(db.Boolean, default=False)
    users = db.relationship('UserEvent', backref='event', lazy=True)

def __repr__(self):
        return f'<Event {self.title}>'


    

class UserEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    def __repr__(self):
        return f'<UserEvent User: {self.user_id}, Event: {self.event_id}>'
# Resource classes
@jwt.unauthorized_loader
@jwt.invalid_token_loader
def custom_error_response(callback):
    resp = callback('Missing or invalid token')
    resp.set_cookie('access_token_cookie', '', max_age=0) 
    resp.set_cookie('refresh_token_cookie', '', max_age=0)
    return resp
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
        if '@' not in email or '.' not in email:
            return {'message': 'Invalid email format'}, 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'Username already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        jwt_key = secrets.token_urlsafe(32)  # Generate a new JWT key
        new_user = User(username=username, email=email, password_hash=hashed_password, phone_number=phone_number, jwt_key=jwt_key)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully', 'jwt_key': jwt_key}, 201

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
            return {'access_token': access_token, 'refresh_token': refresh_token}, 200
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
            response = make_response({'access_token': access_token, 'refresh_token': refresh_token}, 200)
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        response = make_response({'message': 'Invalid credentials'}, 401)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response


class EventList(Resource):
    def get(self):
        try:
            events = Event.query.all()
            return jsonify([event.serialize() for event in events])
        except Exception as e:
            app.logger.error(f"Error fetching events: {e}")
            return {'message': 'Failed to fetch events'}, 500

class EventCreate(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str, required=True, help='Title is required')
        parser.add_argument('description', type=str, required=True, help='Description is required')
        parser.add_argument('ticket_price', type=float, required=True, help='Ticket price is required')
        parser.add_argument('photo_url', type=str, required=True, help='Photo URL is required')
        parser.add_argument('event_date', type=str, required=True, help='Event date is required')
        parser.add_argument('tickets_remaining', type=int, required=True, help='Tickets remaining is required')
        args = parser.parse_args()

        title = args['title']
        description = args['description']
        ticket_price = args['ticket_price']
        photo_url = args['photo_url']
        event_date = datetime.fromisoformat(args['event_date'])
        tickets_remaining = args['tickets_remaining']

        try:
            new_event = Event(
                title=title, description=description, ticket_price=ticket_price, 
                photo_url=photo_url, event_date=event_date, 
                tickets_remaining=tickets_remaining
            )
            db.session.add(new_event)
            db.session.commit()

            return {'message': 'Event created successfully'}, 201

        except Exception as e:
            app.logger.error(f"Error creating event: {e}")
            return {'message': 'Failed to create event'}, 500

class UsersListResource(Resource):
    def get(self):
        users = User.query.all()
        user_list = []
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'phone_number': user.phone_number
            }
            user_list.append(user_data)
        return jsonify(user_list)
class EventUpdate(Resource):
    @jwt_required()
    def put(self, event_id):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str, required=True, help='Title is required')
        parser.add_argument('description', type=str, required=True, help='Description is required')
        parser.add_argument('ticket_price', type=float, required=True, help='Ticket price is required')
        parser.add_argument('photo_url', type=str, required=True, help='Photo URL is required')
        parser.add_argument('event_date', type=str, required=True, help='Event date is required')
        parser.add_argument('tickets_remaining', type=int, required=True, help='Tickets remaining is required')
        args = parser.parse_args()

        try:
            event = Event.query.get(event_id)
            if not event:
                return {'message': 'Event not found'}, 404

            event.title = args['title']
            event.description = args['description']
            event.ticket_price = args['ticket_price']
            event.photo_url = args['photo_url']
            event.event_date = datetime.fromisoformat(args['event_date'])
            event.tickets_remaining = args['tickets_remaining']

            db.session.commit()
            return {'message': 'Event updated successfully'}, 200

        except Exception as e:
            app.logger.error(f"Error updating event: {e}")
            return {'message': 'Failed to update event'}, 500
        
class UserDelete(Resource):
    @jwt_required()
    def delete(self, user_id):
        try:
            user = User.query.get(user_id)
            if not user:
                return {'message': 'User not found'}, 404

            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted successfully'}, 200

        except Exception as e:
            app.logger.error(f"Error deleting user: {e}")
            return {'message': 'Failed to delete user'}, 500
class TokenValidateResource(Resource):
    @jwt_required()
    def get(self):
        # Token is valid, return success message or any data you need
        current_user = get_jwt_identity()
        return {'message': 'Valid token for user {}'.format(current_user)}, 200

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
            return {'access_token': access_token, 'refresh_token': refresh_token}, 200
        return {'message': 'Invalid credentials'}, 401
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_access_token}, 200
class AllEvents(Resource):
    def get(self):
        events = Event.query.all()
        return jsonify([{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'ticket_price': event.ticket_price,
            'photo_url': event.photo_url,
            'event_date': event.event_date.isoformat(),
            'tickets_remaining': event.tickets_remaining
        } for event in events])

    def post(self):
        data = request.get_json()
        new_event = Event(
            title=data['title'],
            description=data['description'],
            ticket_price=data['ticket_price'],
            photo_url=data.get('photo_url'),
            event_date=datetime.fromisoformat(data['event_date']),
            tickets_remaining=data.get('tickets_remaining', 0)
        )
        db.session.add(new_event)
        db.session.commit()
        return {'message': 'Event created successfully'}, 201

class SingleEvent(Resource):
    def get(self, event_id):
        event = Event.query.get_or_404(event_id)
        return jsonify({
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'ticket_price': event.ticket_price,
            'photo_url': event.photo_url,
            'event_date': event.event_date.isoformat(),
            'tickets_remaining': event.tickets_remaining
        })

    def put(self, event_id):
        event = Event.query.get_or_404(event_id)
        data = request.get_json()
        event.title = data['title']
        event.description = data['description']
        event.ticket_price = data['ticket_price']
        event.photo_url = data.get('photo_url')
        event.event_date = datetime.fromisoformat(data['event_date'])
        event.tickets_remaining = data.get('tickets_remaining', event.tickets_remaining)
        db.session.commit()
        return {'message': 'Event updated successfully'}, 200

    def delete(self, event_id):
        event = Event.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        return {'message': 'Event deleted successfully'}, 200

class UserBookmarkedEvents(Resource):
    def get(self, user_id):
        user_events = UserEvent.query.filter_by(user_id=user_id).all()
        event_ids = [user_event.event_id for user_event in user_events]
        events = Event.query.filter(Event.id.in_(event_ids)).all()
        return jsonify([{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'ticket_price': event.ticket_price,
            'photo_url': event.photo_url,
            'event_date': event.event_date.isoformat(),
            'tickets_remaining': event.tickets_remaining
        } for event in events])

    def post(self, user_id):
        data = request.get_json()
        event_id = data.get('event_id')
        if not event_id:
            return {'message': 'Event ID is required'}, 400

        user_event = UserEvent(user_id=user_id, event_id=event_id)
        db.session.add(user_event)
        db.session.commit()
        return {'message': 'Event bookmarked successfully'}, 201

    def delete(self, user_id):
        data = request.get_json()
        event_id = data.get('event_id')
        if not event_id:
            return {'message': 'Event ID is required'}, 400

        user_event = UserEvent.query.filter_by(user_id=user_id, event_id=event_id).first()
        if user_event:
            db.session.delete(user_event)
            db.session.commit()
            return {'message': 'Event unbookmarked successfully'}, 200
        return {'message': 'Event not found'}, 404
class EventDelete(Resource):
    @jwt_required()
    def delete(self, event_id):
        try:
            event = Event.query.get(event_id)
            if not event:
                return {'message': 'Event not found'}, 404

            db.session.delete(event)
            db.session.commit()
            return {'message': 'Event deleted successfully'}, 200

        except Exception as e:
            logger.error(f"Error deleting event: {e}")
            return {'message': 'Failed to delete event'}, 500


api.add_resource(AllEvents, '/events')
api.add_resource(SingleEvent, '/events/<int:event_id>')
api.add_resource(UserBookmarkedEvents, '/user/<int:user_id>/bookmarked-events')
api.add_resource(UserRegister, '/register')
api.add_resource(AdminRegister, '/admin/register')
api.add_resource(UserLogin, '/login')
api.add_resource(AdminLogin, '/admin/login')
api.add_resource(EventList, '/events')
api.add_resource(EventCreate, '/event/create')
api.add_resource(UsersListResource, '/users')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(EventUpdate, '/event/update/<int:event_id>')
api.add_resource(EventDelete, '/event/<int:event_id>/delete')
api.add_resource(UserDelete, '/user/delete/<int:user_id>')
api.add_resource(TokenValidateResource, '/token/validate')


if __name__ == '__main__':
    app.run(debug=True)