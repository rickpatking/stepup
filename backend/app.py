from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db, UserLevel
from config import load_config
from datetime import datetime, date
from functools import wraps
import jwt
import os


app = Flask(__name__)

load_config(app)
db.init_app(app)

def generate_token(user_id):
    return jwt.encode({"user_id": user_id}, app.config['SECRET_KEY'], algorithm="HS256")

def decode_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return data["user_id"]
    except:
        return None

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_pw = generate_password_hash(password)
    user = User(username=username, password_hash=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    token = generate_token(user.id)
    return jsonify({"token": token})


@app.route("/api/user/profile", methods=["GET"])
def profile():
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token[7:]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({"message": "Invalid or missing token"}), 401

    user = User.query.get(user_id)
    user_level = UserLevel.query.filter_by(user_id=user.id).first()
    return jsonify({
        "username": user.username,
        "steps": user.total_steps_life,
        "level": user_level.current_level if user_level else 1,
        "xp": user_level.current_exp if user_level else 0
    })


@app.route("/api/steps/sync", methods=["POST"])
def sync_steps():
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token[7:]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({"message": "Invalid or missing token"}), 401

    data = request.json
    steps_count = data.get("steps_count", 0)

    user = User.query.get(user_id)
    user_level = UserLevel.query.filter_by(user_id=user.id).first()
    user.total_steps_life += steps_count
    level_ups = user_level.add_exp(steps_count // 100)

    db.session.commit()

    return jsonify({
        "message": "Steps updated",
        "total_steps": user.total_steps_life,
        "level": user_level.current_level if user_level else 1,
        "xp": user_level.current_exp if user_level else 0
    })


@app.route("/api/journeys", methods=["GET"])
def journeys():
    return jsonify({
        "journeys": [
            {"id": 1, "name": "New York City, NY to Los Angeles, CA", "distance_mi": 2787},
            {"id": 2, "name": "Chicago, IL to Seattle, WA", "distance_mi": 2048},
            {"id": 3, "name": "Chicago, IL to New York City, NY", "distance_mi": 815},
            {"id": 4, "name": "Los Angeles, CA to Chicago, IL", "distance_mi": 2041},
            {"id": 5, "name": "New York City, NY to Seattle, WA", "distance_mi": 2866},
            {"id": 6, "name": "Seattle, WA to Los Angeles, CA", "distance_mi": 1148}
        ]
    })


@app.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    users = User.query.order_by(User.total_steps_life.desc()).limit(10).all()
    leaderboard_data = [
        {
            "username": u.username,
            "steps": u.total_steps_life,
            "level": u.level_info.current_level if u.level_info else 1
        }
        for u in users
    ]
    return jsonify(leaderboard_data)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # make sure site.db gets created
    app.run(debug=True)