from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, StepLog, Journey, Boss, UserLevel, BossAttack, BossManager
from config import load_config, BADGE_MILESTONES, PRESET_JOURNEYS
from datetime import datetime, date, timedelta
from functools import wraps
import jwt
import os

from dotenv import load_dotenv
load_dotenv()
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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token and token.startswith("Bearer "):
            token = token[7:]
        user_id = decode_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid or missing token'}), 401
        current_user = User.query.get(user_id)
        return f(current_user, *args, **kwargs)
    return decorated

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
@token_required
def profile(current_user):
    # token = request.headers.get("Authorization")
    # if token and token.startswith("Bearer "):
    #     token = token[7:]
    # user_id = decode_token(token)
    # if not user_id:
    #     return jsonify({"message": "Invalid or missing token"}), 401
    #
    # user = User.query.get(user_id)
    # user_level = UserLevel.query.filter_by(user_id=user.id).first()
    # return jsonify({
    #     "username": user.username,
    #     "steps": user.total_steps_life,
    #     "level": user_level.current_level if user_level else 1,
    #     "xp": user_level.current_exp if user_level else 0
    # })
    try:
        user_level = UserLevel.query.filter_by(user_id=current_user.id).first()
        if not user_level:
            user_level = UserLevel(user_id=current_user.id)
            db.session.add(user_level)
            db.session.commit()

        badges = []
        for milestone, badge_info in BADGE_MILESTONES.items():
            if current_user.total_steps_life >= milestone:
                badges.append(badge_info)

        today_steps = current_user.get_today_steps()
        streak = current_user.get_streak()
        journey_info = None
        if current_user.current_journey_id:
            journey = current_user.current_journey
            journey_info = {
                'id': journey.id,
                'start_city': journey.start_city,
                'end_city': journey.end_city,
                'total_distance_miles': journey.total_distance_miles,
                'personal_progress_miles': journey.personal_progress_miles,
                'progress_percentage': round((journey.personal_progress_miles / journey.total_distance_miles) * 100, 2),
                'is_complete': journey.completed_at is not None
            }

        return jsonify({
            "username": current_user.username,
            "display_name": current_user.display_name or current_user.username,
            "total_steps_life": current_user.total_steps_life,
            "today_steps": today_steps,
            "streak": streak,
            "total_miles": round(current_user.total_steps_life / 2000, 2),
            "level": user_level.current_level,
            "current_exp": user_level.current_exp,
            "exp_to_next_level": user_level.exp_to_next_level(),
            "badges": badges,
            "current_journey": journey_info
        })
    except Exception as e:
        return jsonify({'message': 'Failed to get profile'}), 500


@app.route("/api/steps/sync", methods=["POST"])
@token_required
def sync_steps(current_user):
    # token = request.headers.get("Authorization")
    # if token and token.startswith("Bearer "):
    #     token = token[7:]
    # user_id = decode_token(token)
    # if not user_id:
    #     return jsonify({"message": "Invalid or missing token"}), 401
    #
    # data = request.json
    # steps_count = data.get("steps_count", 0)
    #
    # user = User.query.get(user_id)
    # user_level = UserLevel.query.filter_by(user_id=user.id).first()
    # user.total_steps_life += steps_count
    # level_ups = user_level.add_exp(steps_count // 100)
    #
    # db.session.commit()
    #
    # return jsonify({
    #     "message": "Steps updated",
    #     "total_steps": user.total_steps_life,
    #     "level": user_level.current_level if user_level else 1,
    #     "xp": user_level.current_exp if user_level else 0
    # })
    try:
        data = request.json
        steps_count = data.get('steps_count', 0)
        if not isinstance(steps_count, int) or steps_count < 0:
            return jsonify({'message': 'Invalid steps_count'}), 400

        today = date.today()
        user_level = UserLevel.query.filter_by(user_id=current_user.id).first()
        if not user_level:
            user_level = UserLevel(user_id=current_user.id)
            db.session.add(user_level)

        existing_log = StepLog.query.filter_by(
            user_id=current_user.id,
            date=today
        ).first()

        if existing_log:
            steps_difference = steps_count - existing_log.steps_count
            existing_log.steps_count = steps_count
            existing_log.distance_miles = steps_count / 2000
            existing_log.timestamp = datetime.utcnow()
        else:
            steps_difference = steps_count
            new_log = StepLog(
                user_id=current_user.id,
                steps_count=steps_count,
                date=today,
                source=data.get('source', 'healthkit')
            )
            db.session.add(new_log)

        level_ups = 0
        if steps_difference > 0:
            current_user.total_steps_life += steps_difference
            exp_gained = steps_difference // 100
            level_ups = user_level.add_exp(exp_gained)

            if current_user.current_journey_id:
                personal_journey = current_user.current_journey
                if personal_journey and personal_journey.is_active:
                    distance_miles = steps_difference / 2000
                    personal_journey.personal_progress_miles += distance_miles

                    if (personal_journey.personal_progress_miles >= personal_journey.total_distance_miles and not personal_journey.completed_at):
                        personal_journey.completed_at = datetime.utcnow()
                        personal_journey.is_active = False
                        current_user.current_journey_id = None
                        completion_exp = 500
                        level_ups += user_level.add_exp(completion_exp)
        current_user.last_active = datetime.utcnow()
        db.session.commit()

        response_data = {
            'message': 'Steps synced successfully',
            'steps_added': steps_difference,
            'total_steps_today': steps_count,
            'total_steps_life': current_user.total_steps_life,
            'level': user_level.current_level,
            'current_exp': user_level.current_exp,
            'exp_to_next_level': user_level.exp_to_next_level(),
            'level_ups': level_ups
        }
        if current_user.current_journey_id:
            journey = current_user.current_journey
            response_data['journey_progress'] = {
                'journey_name': f'{journey.start_city} to {journey.end_city}',
                'progress_miles': round(journey.personal_progress_miles, 2),
                'total_miles': journey.total_distance_miles,
                'progress_percentage': round((journey.personal_progress_miles / journey.total_distance_miles) * 100, 2),
                'miles_added': round(steps_difference/2000, 2),
                'is_completed': journey.completed_at is not None
            }
            if journey.completed_at and journey.completed_at > (datetime.utcnow() - timedelta(minutes=1)):
                response_data['completion_message'] = f'Congratulations! You completed your journey from {journey.start_city} to {journey.end_city}!'
        return jsonify(response_data)
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to sync steps'}), 500

@app.route('/api/steps/history', methods=['GET'])
@token_required
def get_step_history(current_user):
    try:
        days = request.args.get('days', 30, type=int)
        days = min(days, 365)
        step_logs = StepLog.query.filter_by(user_id=current_user.id).order_by(StepLog.date.desc()).limit(days).all()
        return jsonify({
            'step_history': [log.to_dict() for log in step_logs],
            'total_days': len(step_logs)
        })
    except Exception as e:
        return jsonify({'message': 'Failed to get step history'}), 500

@app.route("/api/journeys", methods=["GET"])
def journeys():
    try:
        journey_templates = Journey.query.filter_by(is_template=True, is_active=True).all()
        return jsonify({'journeys': [j.to_dict() for j in journey_templates]})
    except Exception as e:
        return jsonify({'message': 'Failed to get journeys'}), 500


@app.route('/api/journeys/<int:template_id>/start', methods=['POST'])
@token_required
def start_journey(current_user, template_id):
    try:
        template = Journey.query.filter_by(id=template_id, is_template=True).first()
        if not template:
            return jsonify({'message': 'Journey template not found'}), 404
        if current_user.current_journey_id:
            return jsonify({'message': 'Please complete current journey first'}), 400

        personal_journey = Journey(
            user_id=current_user.id,
            template_id=template_id,
            start_city=template.start_city,
            end_city=template.end_city,
            description=template.description,
            total_distance_miles=template.total_distance_miles,
            difficulty=template.difficulty,
            personal_progress_miles=0.0,
            is_template=False
        )
        db.session.add(personal_journey)
        db.session.flush()

        current_user.current_journey_id = personal_journey.id
        db.session.commit()
        return jsonify({
            'message': f'Started journey: {template.start_city} to {template.end_city}',
            'journey': personal_journey.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to start journey'}), 500

@app.route('/api/journeys/end', methods=['POST'])
@token_required
def end_journey(current_user):
    try:
        if not current_user.current_journey_id:
            return jsonify({'message': 'Not currently on a journey'}), 400
        current_user.current_journey_id = None
        current_user.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Successfully ended journey'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to end journey'}), 500

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

@app.route('/api/bosses', methods=['GET'])
@token_required
def get_bosses(current_user):
    try:
        journey_id = current_user.current_journey_id
        bosses = BossManager.get_available_bosses(
            user_id=current_user.id,
            journey_id=journey_id
        )
        return jsonify({
            'bosses': [boss.to_dict() for boss in bosses]
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to get bosses'}), 500

@app.route('/api/bosses/<int:boss_id>/attack', methods=['POST'])
@token_required
def attack_boss(current_user, boss_id):
    try:
        data = request.get_json()
        if not data or 'steps_to_use' not in data:
            return jsonify({'error': 'steps_to_use required'}), 400
        steps_to_use = data['steps_to_use']
        if not isinstance(steps_to_use, int) or steps_to_use <= 0:
            return jsonify({'error': 'steps_to_use must be a postive integer'}), 400

        today = date.today()
        today_log = StepLog.query.filter_by(user_id=current_user.id, date=today).first()
        available_steps = today_log.steps_count if today_log else 0

        if steps_to_use > available_steps:
            return jsonify({
                'error': 'Insufficient steps',
                'available_steps': available_steps,
                'requested_steps': steps_to_use
            }), 400

        result = BossManager.attack_boss(current_user, boss_id, steps_to_use)

        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to attack boss'}), 500

@app.route('/')
def home():
    return jsonify({
        'api': 'StepUp Backend',
        'version': '1.0',
        'status': 'running',
        'endpoints': {
            'auth': ['/api/register', '/api/login'],
            'user': ['/api/user/profile'],
            'steps': ['/api/steps/sync', '/api/steps/history'],
            'journeys': ['/api/journeys', '/api/journeys/<id>/join', '/api/journeys/leave'],
            'leaderboard': ['/api/leaderboard'],
            'bosses': ['/api/bosses', '/api/bosses/<id>/attack']
        }
    })

@app.before_first_request
def create_tables():
    db.create_all()
    if Journey.query.filter_by(is_template=True).count() == 0:
        print('Creating journey templates...')
        for journey_data in PRESET_JOURNEYS:
            template = Journey(
                is_template=True,
                user_id=None,
                **journey_data
            )
            db.session.add(template)
        db.session.commit()
        print(f'Created {len(PRESET_JOURNEYS)} journey templates')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_tables()
    app.run(debug=True)