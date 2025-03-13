from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import enum

db = SQLAlchemy()

class UserRole(enum.Enum):
    ADMIN = 'admin'
    MERCHANT = 'merchant'
    AGENT = 'agent'

    def __str__(self):
        return self.value

class TransactionStatus(enum.Enum):
    PENDING = 'pending'
    SUCCESS = 'success'
    FAILED = 'failed'

    def __str__(self):
        return self.value

# Define Enum with Uppercase Values
class QRCodeEntityType(enum.Enum):
    AGENT = 'AGENT'
    TILL = 'TILL'
    PAYBILL = 'PAYBILL'
    POCHI = 'POCHI'

    def __str__(self):
        return self.value

# Association Table for Many-to-Many Relationship between User and Shop (if needed)
shop_managers = db.Table('shop_managers',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('shop_id', db.Integer, db.ForeignKey('merchants.id'), primary_key=True)
)

# Users Table (For Admins and Merchants managing the system)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)

    managed_shops = db.relationship('Merchant', secondary=shop_managers, back_populates='managers')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User id={self.id}, email={self.email}, role={self.role.value}>'

    def as_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "phone_number": self.phone_number,
            "role": self.role.value,
            "full_name": self.full_name,
            "created_at": self.created_at.isoformat()
        }

# MPesa Agents Table
class MPesaAgent(db.Model):
    __tablename__ = 'mpesa_agents'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    store_name = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    store_number = db.Column(db.String(20), nullable=False, unique=True)
    agent_number = db.Column(db.String(20), nullable=False, unique=True)
    location = db.Column(db.String(255))
    qr_code_url = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key to User
    email = db.Column(db.String(255), nullable=False)  # Added email field
    agent_type = db.Column(db.String(50), nullable=False, default="Agent")


    transactions = db.relationship('Transaction', backref='mpesa_agent', lazy=True)
    qr_code = db.relationship('QRCode', backref='mpesa_agent', lazy=True, uselist=False)

    def __repr__(self):
        return f'<MPesaAgent id={self.id}, store_name={self.store_name}, store_number={self.store_number}>'

    def as_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "store_name": self.store_name,
            "phone_number": self.phone_number,
            "store_number": self.store_number,
            "agent_number": self.agent_number,
            "location": self.location,
            "qr_code_url": self.qr_code_url,
            "created_at": self.created_at.isoformat(),
            "email": self.email,  # Added email field
            "agent_type": self.agent_type  # Added agent_type field
        }

# Merchants Table (representing Shops/Businesses)
class Merchant(db.Model):
    __tablename__ = 'merchants'
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    till_number = db.Column(db.String(20), unique=True, nullable=True)
    paybill_number = db.Column(db.String(20), unique=True, nullable=True)
    pochi_number = db.Column(db.String(20), unique=True, nullable=True)
    account_number = db.Column(db.String(20), unique=True, nullable=True)
    qr_code_url = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    merchant_type = db.Column(db.Enum('Paybill', 'Till', 'Pochi', name='merchant_type'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key to User
    email = db.Column(db.String(255), nullable=False)  # Added email field

    transactions = db.relationship('Transaction', backref='merchant', lazy=True)
    till_qr_code = db.relationship('QRCode', backref='merchant_till', lazy=True, foreign_keys='QRCode.merchant_till_id', uselist=False)
    paybill_qr_code = db.relationship('QRCode', backref='merchant_paybill', lazy=True, foreign_keys='QRCode.merchant_paybill_id', uselist=False)
    pochi_qr_code = db.relationship('QRCode', backref='merchant_pochi', lazy=True, foreign_keys='QRCode.merchant_pochi_id', uselist=False)
    managers = db.relationship('User', secondary=shop_managers, back_populates='managed_shops')

    def __repr__(self):
        return f'<Merchant id={self.id}, business_name={self.business_name}, full_name={self.full_name}>'

    def as_dict(self):
        return {
            "id": self.id,
            "business_name": self.business_name,
            "phone_number": self.phone_number,
            "full_name": self.full_name,
            "till_number": self.till_number,
            "paybill_number": self.paybill_number,
            "pochi_number": self.pochi_number,
            "account_number": self.account_number,
            "qr_code_url": self.qr_code_url,
            "created_at": self.created_at.isoformat(),
            "merchant_type": self.merchant_type.value,
            "email": self.email  # Added email field
        }

# Transactions Table
class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('mpesa_agents.id'), nullable=True)  # Foreign Key to M-Pesa Agents table
    merchant_id = db.Column(db.Integer, db.ForeignKey('merchants.id'), nullable=True)  # Foreign Key to Merchants table
    amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    status = db.Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING, nullable=False)
    transaction_type = db.Column(db.Enum('Withdrawal', 'Till Payment', 'Paybill Payment', 'Pochi Payment'), nullable=False)  # Enum for transaction type
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    customer_msisdn = db.Column(db.String(20))  # Customer's phone number, VARCHAR, not a ForeignKey

    def __repr__(self):
        return f'<Transaction id={self.id}, amount={self.amount}, status={self.status}>'

    def as_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "merchant_id": self.merchant_id,
            "amount": float(self.amount),
            "status": self.status.value,
            "transaction_type": self.transaction_type,
            "created_at": self.created_at.isoformat(),
            "customer_msisdn": self.customer_msisdn,
        }

# Base QR Code Table
class QRCode(db.Model):
    __tablename__ = 'qr_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.Integer, nullable=False)  # Linked entity (Agent or Merchant)
    
    # Store Enum as a String to prevent LookupError
    identity_type = db.Column(db.String(20), nullable=False)  
    
    qr_code_url = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)

    # Foreign keys for different merchant types
    agent_id = db.Column(db.Integer, db.ForeignKey('mpesa_agents.id'), nullable=True)  
    merchant_till_id = db.Column(db.Integer, db.ForeignKey('merchants.id'), nullable=True)  
    merchant_paybill_id = db.Column(db.Integer, db.ForeignKey('merchants.id'), nullable=True)  
    merchant_pochi_id = db.Column(db.Integer, db.ForeignKey('merchants.id'), nullable=True)  

    __mapper_args__ = {
        'polymorphic_identity': 'QRCode',
        'polymorphic_on': identity_type
    }

    def __repr__(self):
        return f'<QRCode id={self.id}, identity_type={self.identity_type}, entity_id={self.entity_id}>'

    def as_dict(self):
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "identity_type": self.identity_type,
            "qr_code_url": self.qr_code_url,
            "created_at": self.created_at.isoformat()
        }

# Subclasses for Polymorphic Identity Mapping
class AgentQRCode(QRCode):
    __mapper_args__ = {
        'polymorphic_identity': QRCodeEntityType.AGENT.value
    }

class TillQRCode(QRCode):
    __mapper_args__ = {
        'polymorphic_identity': QRCodeEntityType.TILL.value
    }

class PaybillQRCode(QRCode):
    __mapper_args__ = {
        'polymorphic_identity': QRCodeEntityType.PAYBILL.value
    }

class PochiQRCode(QRCode):
    __mapper_args__ = {
        'polymorphic_identity': QRCodeEntityType.POCHI.value
    }