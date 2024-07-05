# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate  # Add this line
from flask_cors import CORS  # Add this line

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate()  # Create an instance of Migrate
cors = CORS()  # Create an instance of CORS