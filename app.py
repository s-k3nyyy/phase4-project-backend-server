from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity
from auth import jwt, auth_bp, bcrypt, allow
from models import db, EventBookmark, Payment, Ticket, Event, User, Role, TokenBlocklist
from flask_restful import Api, Resource
from sqlalchemy.orm import Session
from datetime import timedelta, datetime


app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'bfd44160eee50045cba10da003f8267b'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=10)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=15)
app.json.compact = False

migrate = Migrate(app, db)


app.register_blueprint(auth_bp)
db.init_app(app)
jwt.init_app(app)
bcrypt.init_app(app)
api=Api(app)


@app.route('/')
def index():
    return f'Welcome to phase 4 Project'


@app.route('/check_admin', methods=['GET'])
@jwt_required()
def check_admin():
    current_user_id = get_jwt_identity()
    session = Session(db.engine)
    user = session.get(User, current_user_id)
    if user and any(role.name == 'admin' for role in user.roles):
        return jsonify(is_admin=True), 200
    return jsonify(is_admin=False), 200


class Users(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        return make_response(users, 200)
    

    def post(self):
        data = request.get_json()

        if not data or not data.get('username') or not data.get('email'):
            return {"message": "Required (username and email)"}, 400

        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return {"message": "User with this email already exists"}, 400
        
        new_user = User(username=data['username'], email=data['email'])
        try:
            db.session.add(new_user)
            db.session.commit()
            user_dict = new_user.to_dict()
            response = make_response(user_dict, 201)
            return response
        
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error creating user", "error": str(exc)}, 500

api.add_resource(Users, '/users')


class UserById(Resource):
    def get(self, id):
        user = User.query.filter(User.id == id).first()
        if not user:
            return {"message": "User not found"}, 404
        return user.to_dict(), 200

    def patch(self, id):
        user = User.query.filter_by(id=id).first()
        if not user:
            return {"message": "User not found"}, 404
        
        data = request.get_json()
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        try:
            db.session.commit()
            return user.to_dict(), 200
        except Exception as e:
            db.session.rollback()
            return {"message": "Error updating user", "error": str(e)}, 500

    def delete(self, id):
        user = User.query.filter_by(id=id).first()
        if not user:
            return {"message": "User not found"}, 404
        try:
            db.session.delete(user)
            db.session.commit()
            return {}, 204
        except Exception as e:
            db.session.rollback()
            return {"message": "Error deleting user", "error": str(e)}, 500

api.add_resource(UserById, '/users/<int:id>')






class EventBookmarks(Resource):
    def get(self):
        eventbookmarks = [eventbookmark.to_dict() for eventbookmark in EventBookmark.query.all()]
        return make_response(eventbookmarks, 200)
    
    @jwt_required()
    @allow('admin')
    def post(self):
        data = request.get_json()
        if not data or not data.get('user_id') or not data.get('event_id'):
            return {"message": "Required (user_id and event_id)"}, 400

        user = db.session.get(User, data['user_id'])
        if not user:
            return {"message": "User not found"}, 404

        event = db.session.get(Event, data['event_id'])
        if not event:
            return {"message": "Event not found"}, 404

        new_eventbookmark = EventBookmark(user_id=data['user_id'], event_id=data['event_id'])
        try:
            db.session.add(new_eventbookmark)
            db.session.commit()
            return {"message": "EventBookmark created Successfully", "eventbookmark": new_eventbookmark.to_dict()}, 201
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error creating event bookmark", "error": str(exc)}, 500   
    
api.add_resource(EventBookmarks, '/eventbookmarks')



class EventBookmarkById(Resource):
    @jwt_required()
    @allow('admin')
    def get(self, id):
        eventbookmark = EventBookmark.query.filter(EventBookmark.id==id).first()
        if not eventbookmark:
            return {"message": "EventBookmark not found"}, 404
        return eventbookmark.to_dict(), 200
    
    @jwt_required()
    @allow('admin')
    def patch(self, id):
        data = request.get_json()

        eventbookmark = EventBookmark.query.filter(EventBookmark.id==id).first()
        if not eventbookmark:
            return {"message": "Event bookmark not found"}, 404

        if 'user_id' in data:
            eventbookmark.user_id = data['user_id']
        if 'event_id' in data:
            eventbookmark.event_id = data['event_id']
        
        try:
            db.session.commit()
            return eventbookmark.to_dict(), 200
        except Exception as e:
            db.session.rollback()
            return {"message": "Error updating event bookmark", "error": str(e)}, 500
    
    @jwt_required()
    @allow('admin')
    def delete(self, id):
        eventbookmark = EventBookmark.query.filter(EventBookmark.id==id).first()
        if not eventbookmark:
            return {"message": "Event bookmark not found"}, 404
        
        try:
            db.session.delete(eventbookmark)
            db.session.commit()
            return {}, 204
        except Exception as e:
            db.session.rollback()
            return {"message": "Error deleting event bookmark", "error": str(e)}, 500

api.add_resource(EventBookmarkById, '/eventbookmarks/<int:id>')





class Payments(Resource):
    def get(self):
        payments = [payment.to_dict() for payment in Payment.query.all()]
        return make_response(jsonify(payments), 200)

    def post(self):
        data = request.get_json()
        if not data or not data.get('amount') or not data.get('status') or not data.get('user_id') or not data.get('event_id') or not data.get('ticket_id'):
            return {"message": "Required (amount, status, user_id, event_id, ticket_id)"}, 400

        user = db.session.get(User, data['user_id'])
        if not user:
            return {"message": "User not found"}, 404

        event_id = data.get('event_id')
        if event_id:
            event = db.session.get(Event, event_id)
            if not event:
                return {"message": "Event not found"}, 404

        ticket_id = data.get('ticket_id')
        if ticket_id:
            ticket = db.session.get(Ticket, ticket_id)
            if not ticket:
                return {"message": "Ticket not found"}, 404

        new_payment = Payment(
            amount=data['amount'],
            status=data['status'],
            user_id=data['user_id'],
            event_id=event_id,
            ticket_id=ticket_id
        )

        try:
            db.session.add(new_payment)
            db.session.commit()
            return {"message": "Payment created successfully", "payment": {
                "id": new_payment.id,
                "amount": new_payment.amount,
                "status": new_payment.status,
                "created_at": new_payment.created_at.isoformat(),
                "updated_at": new_payment.updated_at.isoformat() if new_payment.updated_at else None,
                "user_id": new_payment.user_id,
                "event_id": new_payment.event_id,
                "ticket_id": new_payment.ticket_id
            }}, 201
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error creating payment", "error": str(exc)}, 500

api.add_resource(Payments, '/payments')


class PaymentById(Resource):
    def get(self, id):
        payment = Payment.query.filter(Payment.id==id).first()
        if not payment:
            return {"message": "Payment not found"}, 404
        return payment.to_dict(), 200


    def patch(self, id):
        payment = db.session.get(Payment, id)
        if not payment:
            return {"message": "Payment not found"}, 404

        data = request.get_json()
        if not data:
            return {"message": "No input data provided"}, 400

        if 'amount' in data:
            payment.amount = data['amount']
        if 'status' in data:
            payment.status = data['status']
        if 'user_id' in data:
            payment.user_id = data['user_id']
        if 'event_id' in data:
            payment.event_id = data['event_id']
        if 'ticket_id' in data:
            payment.ticket_id = data['ticket_id']

        try:
            db.session.commit()
            return {"message": "Payment updated successfully", "payment": {
                "id": payment.id,
                "amount": payment.amount,
                "status": payment.status,
                "created_at": payment.created_at.isoformat(),
                "updated_at": payment.updated_at.isoformat() if payment.updated_at else None,
                "user_id": payment.user_id,
                "event_id": payment.event_id,
                "ticket_id": payment.ticket_id
            }}
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error updating payment", "error": str(exc)}, 500


    def delete(self, id):
        payment = Payment.query.filter_by(id=id).first()
        if not payment:
            return {"message": "Payment not found"}, 404

        try:
            db.session.delete(payment)
            db.session.commit()
            return {}, 204
        
        except Exception as e:
            db.session.rollback()
            return {"message": "Error deleting payment", "error": str(e)}, 500

api.add_resource(PaymentById, '/payments/<int:id>')





class Tickets(Resource):
    def get(self):
        tickets = [ticket.to_dict() for ticket in Ticket.query.all()]
        return make_response(tickets, 200)
    

    def post(self):
        data = request.get_json()
        if not data or not data.get('ticket_type') or not data.get('price') or not data.get('status') or not data.get('event_id'):
            return {"message": "Required (ticket_type, price, status, event_id)"}, 400
        
        new_ticket = Ticket(
            ticket_type=data['ticket_type'],
            price=data['price'],
            status=data['status'],
            event_id=data['event_id']
        )

        try:
            db.session.add(new_ticket)
            db.session.commit()
            return {"message": "Ticket created successfully", "ticket": new_ticket.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": "Error creating ticket", "error": str(e)}, 500
    
api.add_resource(Tickets, '/tickets')



class TicketById(Resource):
    def get(self, id):
        ticket = db.session.get(Ticket, id)
        if not ticket:
            return {"message": "Ticket not found"}, 404
        return ticket.to_dict(), 200
    

    def patch(self, id):
        ticket = db.session.get(Ticket, id)
        if not ticket:
            return {"message": "Ticket not found"}, 404

        data = request.get_json()
        if not data:
            return {"message": "No input data provided"}, 400

        if 'ticket_type' in data:
            ticket.ticket_type = data['ticket_type']
        if 'price' in data:
            ticket.price = data['price']
        if 'status' in data:
            ticket.status = data['status']
        if 'event_id' in data:
            ticket.event_id = data['event_id']

        try:
            db.session.commit()
            return {
                "message": "Ticket updated successfully",
                "ticket": ticket.to_dict()
            }
        except Exception as e:
            db.session.rollback()
            return {"message": "Error updating ticket", "error": str(e)}, 500
        

    def delete(self, id):
        ticket = db.session.get(Ticket, id)
        if not ticket:
            return {"message": "Ticket not found"}, 404

        try:
            db.session.delete(ticket)
            db.session.commit()
            return {}, 204
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error deleting ticket", "error": str(exc)}, 500

api.add_resource(TicketById, '/tickets/<int:id>')





class Events(Resource):
    def get(self):
        events = [event.to_dict() for event in Event.query.all()]
        return make_response(events, 200)
    
    @jwt_required()
    @allow('admin')
    def post(self):
        data = request.get_json()
        try:
            date_time = datetime.strptime(data.get('date_time'), '%Y-%m-%d %H:%M:%S')

            new_event = Event(
                title=data.get('title'),
                description=data.get('description'),
                location=data.get('location'),
                date_time=date_time,
                organizer_id=data.get('organizer_id')
            )

            db.session.add(new_event)
            db.session.commit()
            return make_response(jsonify(new_event.to_dict()), 201)
        except ValueError as e:
            db.session.rollback()
            return make_response(jsonify({"message": "Error parsing date_time", "error": str(e)}), 400)
        except Exception as e:
            db.session.rollback()
            return make_response(jsonify({"message": "Error creating event", "error": str(e)}), 500)
    
api.add_resource(Events, '/events')


class EventById(Resource):
    @jwt_required()
    @allow('admin')
    def get(self, id):
        event = Event.query.filter(Event.id == id).first()
        if not event:
            return {"message": "Event not found"}, 404
        return event.to_dict(), 200

    @jwt_required()
    @allow('admin')
    def patch(self, id):
        event = Event.query.filter_by(id=id).first()
        if not event:
            return make_response(jsonify({"message": "Event not found"}), 404)

        data = request.get_json()

        if 'title' in data:
            event.title = data['title']
        if 'description' in data:
            event.description = data['description']
        if 'location' in data:
            event.location = data['location']
        if 'date_time' in data:
            try:
                event.date_time = datetime.strptime(data['date_time'], '%Y-%m-%d %H:%M:%S')
            except ValueError as exc:
                return make_response(jsonify({"message": "Error parsing date_time", "error": str(exc)}), 400)
        if 'organizer_id' in data:
            event.organizer_id = data['organizer_id']

        try:
            db.session.commit()
            return make_response(jsonify(event.to_dict()), 200)
        except Exception as exc:
            db.session.rollback()
            return make_response(jsonify({"message": "Error updating event", "error": str(exc)}), 500)

    @jwt_required()
    @allow('admin')
    def delete(self, id):
        event = Event.query.filter_by(id=id).first()
        if not event:
            return {"message": "Event not found"}, 404
        try:
            db.session.delete(event)
            db.session.commit()
            return {}, 204
        except Exception as exc:
            db.session.rollback()
            return {"message": "Error deleting Event", "error": str(exc)}, 500

api.add_resource(EventById, '/events/<int:id>')




class Roles(Resource):
    def get(self):
        roles = [role.to_dict() for role in Role.query.all()]
        return make_response(roles, 200)


api.add_resource(Roles, '/roles')


class RoleById(Resource):
    def get(self, id):
        role = Role.query.filter(Role.id == id).first()
        if not role:
            return {"message": "Role not found"}, 404
        return role.to_dict(), 200


api.add_resource(RoleById, '/roles/<int:id>')

if __name__ == '__main__':
    app.run(port='5555', debug=True)