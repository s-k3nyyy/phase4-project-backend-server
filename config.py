import os

# Flask app configuration
SECRET_KEY = 'your_secret_key_here'
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'  # SQLite for simplicity
SQLALCHEMY_TRACK_MODIFICATIONS = False
