from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from sqlalchemy.orm import relationship
from sqlalchemy import UniqueConstraint

db = SQLAlchemy()

class User(db.model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), unique=True, nullable=False)

    def __repr__(self):
        return f"User('')"