from random import randint, choice as rc
from faker import Faker
from app import app, db
from models import User, Event, Ticket, Payment, EventBookmark
from werkzeug.security import generate_password_hash

fake = Faker()

with app.app_context():

    print("Deleting all records...")
    db.session.query(User).delete()
    db.session.query(Event).delete()
    db.session.query(Ticket).delete()
    db.session.query(Payment).delete()
    db.session.query(EventBookmark).delete()

    fake  = Faker()


    print("Creating Users...")
    users = []
    for _ in range(3):
        username = fake.first_name()
        while User.query.filter_by(username=username).first() is not None:
            username = fake.first_name()

        email = fake.email()
        password = generate_password_hash("password123")  # Generate a password hash
        user = User(username=username, email=email, password=password)
        users.append(user)

    db.session.add_all(users)
    db.session.commit()



    print("Creating Events...")
    events = []
    for _ in range(10):
        event = Event(
            title=fake.sentence(),
            description=fake.paragraph(),
            location=fake.city(),
            date_time=fake.date_time_this_year(),
            organizer_id=fake.random_element(elements=User.query.all()).id  # Randomly assign organizer from existing users
        )
        events.append(event)

    db.session.add_all(events)
    db.session.commit()



    print("Creating tickets...")
    tickets = []
    for event in events:
        for _ in range(randint(1, 3)):
            ticket = Ticket(
                ticket_type=fake.word(),
                price=fake.random_number(digits=2),
                status=rc(['Available', 'Sold Out', 'Pending']),
                event_id=event.id
            )
            tickets.append(ticket)

    db.session.add_all(tickets)
    db.session.commit()



    print("Creating payments...")
    payments = []
    for _ in range(3):
        payment = Payment(
            amount=fake.random_number(digits=3),
            status=rc(['Success', 'Pending', 'Failed']),
            user_id=fake.random_element(elements=User.query.all()).id,
            event_id=fake.random_element(elements=Event.query.all()).id,
            ticket_id=fake.random_element(elements=Ticket.query.all()).id
        )
        payments.append(payment)

    db.session.add_all(payments)
    db.session.commit()



    print("Creating event bookmarks...")
    event_bookmarks = []
    for user in users:
        for _ in range(randint(1, 3)):
            event_bookmark = EventBookmark(
                user_id=user.id,
                event_id=fake.random_element(elements=Event.query.all()).id
            )
            event_bookmarks.append(event_bookmark)

    db.session.add_all(event_bookmarks)
    db.session.commit()



    print("Database seeding completed successfully.")