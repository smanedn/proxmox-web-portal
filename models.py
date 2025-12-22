from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    #relazione con le richieste
    requests = db.relationship('VMRequest', backref='user', lazy=True)

class VMRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vm_type = db.Column(db.String(20), nullable=False)  # bronze, silver, gold
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    vm_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)
    password = db.Column(db.String(100), nullable=True)