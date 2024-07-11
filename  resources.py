from flask_restful import Resource, reqparse
from models import User, db

class UserRegistration(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help="Username is required")
        parser.add_argument('email', type=str, required=True, help="Email is required")
        parser.add_argument('password', type=str, required=True, help="Password is required")
        parser.add_argument('phone_number', type=str, required=True, help="Phone number is required")
        args = parser.parse_args()

        username = args['username']
        email = args['email']
        password = args['password']
        phone_number = args['phone_number']

        # Check if user already exists
        if User.query.filter_by(username=username).first() is not None:
            return {'message': 'Username already exists'}, 400

        if User.query.filter_by(email=email).first() is not None:
            return {'message': 'Email already registered'}, 400

        # Create a new user
        new_user = User(username=username, email=email, phone_number=phone_number)
        new_user.set_password(password)
        
        # Add user to the database
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201
