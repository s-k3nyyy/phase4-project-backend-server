from flask import Flask
from config import Config
from extensions import db, bcrypt, jwt, migrate, cors

from routes.auth import auth_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(app)

    app.register_blueprint(auth_bp)

    @app.route('/')
    def index():
        return 'Welcome to my Flask app!'

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)