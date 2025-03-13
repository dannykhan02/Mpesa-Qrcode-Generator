from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_mail import Mail
from flask_restful import Api
from flask_migrate import Migrate
from config_settings import Config
from auth import auth_bp
from qr_code_generator import register_qrcode_resources
from oauth_config import init_oauth
from models import db  # Assuming you have a models.py file with db = SQLAlchemy()
from email_utils import mail  # Import the mail object

# Initialize Flask app
app = Flask(__name__)

# Set app configuration
app.config.from_object(Config)

# Ensure SESSION_SQLALCHEMY is set to use the existing db instance
app.config['SESSION_TYPE'] = 'sqlalchemy'  # Store sessions in the database
app.config['SESSION_SQLALCHEMY'] = db  # Use existing SQLAlchemy instance

# Initialize extensions
jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)
init_oauth(app)
mail.init_app(app)  # Initialize Mail with the Flask app
Session(app)  # Initialize session after setting SESSION_SQLALCHEMY

# Register authentication blueprint
app.register_blueprint(auth_bp, url_prefix="/auth")

# Register QR code resources
register_qrcode_resources(api)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
