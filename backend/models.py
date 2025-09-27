from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
from numba.scripts.generate_lower_listing import description
from sqlalchemy.orm import relationship
from sqlalchemy import UniqueConstraint

db = SQLAlchemy()

class User(db.model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), unique=True, nullable=False)

    avatar_url = db.Column(db.String(200), default='')
    display_name = db.Column(db.String(100), nullable=True)
    total_steps_life = db.Column(db.Integer, default=0, nullable=False)

    step_logs = db.relationship('StepLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    current_journey = db.relationship('Journey', foreign_keys=[current_journey_id])

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username, password, **kwargs):
        self.username = username
        self.password = password
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name or self.username,
            'avatar_url': self.avatar_url,
            'bio': self.bio,
            'total_steps_life': self.total_steps_life,
            'current_journey_id': self.current_journey_id,
            'created_at': self.created_at.isoformat(),
            'last_active': self.last_active.isoformat(),
            'is_public': self.is_public
        }
        if include_sensitive:
            data['email'] = self.email
        return data

    def get_today_steps(self):
        today = date.today()
        log = self.step_logs.filter_by(date=today).first()
        return log.steps_count if log else 0

    def get_streak(self):
        today = date.today()
        streak = 0
        while True:
            log = self.step_logs.filter_by(date=today).first()
            if log and log.steps_count > 0:
                streak += 1
                today = today.replace(day=today.day - 1)
            else:
                break
        return streak

class StepLog(db.Model):
    __tablename__ = 'step_logs'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Float, nullable=True)

    steps_count = db.Column(db.Integer, nullable=False, default = 0)
    distance_miles = db.Column(db.Float, nullable=True)

    date = db.Column(db.Date, nullable=False, default = date.today, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    source = db.Column(db.String(50), default='healthkit')

    def __init__(self, user_id, steps_count, date=None, **kwargs):
        self.user_id = user_id
        self.steps_count = steps_count
        self.date = date or date.today()

        #Something for distance_miles

        for key, value in kwargs:
            if hasattr(self, key):
                setattr(self, key, value)

    def __repr__(self):
        return f"StepLog {self.user_id}: {self.steps_count} steps on {self.date}"

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'steps_count': self.steps_count,
            'distance_miles': round(self.distance_miles, 2) if self.distance_miles else 0,
            'date': self.date.isoformat(),
            'timestamp': self.timestamp.isoformat(),
            'source': self.source
        }

class Journey(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)

    start_city = db.Column(db.String(100), nullable=False)
    end_city = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

    total_distance_miles = db.Column(db.Float, nullable=False)
    personal_progress_miles = db.Column(db.Float, default=0.0, nullable=False)

    status = db.Column(db.String(20), default='In Progress')
    difficulty = db.Column(db.string(20), default='Medium')

    is_active = db.Column(db.Boolean, default=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, start_city, end_city, total_distance_miles, **kwargs):
        self.start_city = start_city
        self.end_city = end_city
        self.total_distance_miles = total_distance_miles
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __repr__(self):
        return f"Journey from {self.start_city} to {self.end_city}"

    def to_dict(self):
        return {
            'id': self.id,
            'start_city': self.start_city,
            'end_city': self.end_city,
            'description': self.description,
            'total_distance_miles': self.total_distance_miles,
            'personal_progress_miles': self.personal_progress_miles,
            'status': self.status,
            'difficulty': self.difficulty,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'progress_percentage': self.get_progress_percentage(),
        }

    def get_progress_percentage(self):
        if self.total_distance_miles == 0:
            return 0
        return round((self.personal_progress_miles)/(self.total_distance_miles) * 100, 2)

    def is_complete(self):
        return self.personal_progress_miles >= self.total_distance_miles

    def get_remaining_miles(self):
        return self.total_distance_miles - self.personal_progress_miles

class Boss(db.Model):
    __tablename__ = 'bosses'
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=True)

    max_health = db.Column(db.Integer, nullable=False)
    current_health = db.column(db.Integer, nullable=False)

    exp_reward = db.Column(db.Integer, nullable=False)
    coin_reward = db.Column(db.Integer, default=0)
    special_reward = db.Column(db.String(100), nullable=True)

    difficulty = db.Column(db.String(20), default='Normal')
    boss_type = db.Column(db.String(30), default='Personal')

    journey_id = db.Column(db.Integer, db.ForeignKey('journeys.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    spawned_at = db.Column(db.DateTime, default=datetime.utcnow)
    defeated_at = db.Column(db.DateTime, nullable=True)
    respawn_hours = db.Column(db.Integer, default=24)

    def __repr__(self):
        return f'Boss {self.name}: {self.current_health}/{self.max_health} HP'

    def take_damage(self, steps):
        damage = steps
        self.current_health = self.current_health - damage
        if self.current_health < 0 and self.is_active:
            self.defeated_at = datetime.utcnow()
            self.is_active = False
        #     return True
        # return False

    def is_defeated(self):
        return self.current_health < 0 or (not self.is_active)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'max_health': self.max_health,
            'current_health': self.current_health,
            'health_percentage': self.get_health_percentage(),
            'exp_reward': self.exp_reward,
            'difficulty': self.difficulty,
            'boss_type': self.boss_type,
            'journey_id': self.journey_id,
            'is_active': self.is_active,
            'is_defeated': self.is_defeated(),
            'spawned_at': self.spawned_at.isoformat() if self.spawned_at else None,
            'defeated_at': self.defeated_at.isoformat() if self.defeated_at else None
        }

class UserLevel(db.Model):
    __tablename__ = 'user_levels'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)

    current_level = db.Column(db.Integer, default=1)
    current_exp = db.Column(db.Integer, default=0)
    total_exp = db.Column(db.Integer, default=0)
    attack_power = db.Column(db.Integer, default=1)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_levelup = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='level_info')

    def exp_to_next_level(self):
        return self.calculate_exp_for_level(self.current_level+1) - self.total_exp

    def exp_for_current_level(self):
        return self.calculate_exp_for_level(self.current_level)

    @staticmethod
    def calculate_exp_for_level(level):
        if level <= 1:
            return 0
        return int(100 * (level**1.5))

    def add_exp(self, exp_amount):
        self.current_exp += exp_amount
        self.total_exp += exp_amount

        level_ups = 0
        while self.total_exp >= self.calculate_exp_for_level(self.current_level+1):
            self.current_level += 1
            self.last_levelup = datetime.utcnow()
            level_ups += 1

        current_level_exp = self.calculate_exp_for_level(self.current_level)
        self.current_exp = self.total_exp - current_level_exp
        return level_ups

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'current_level': self.current_level,
            'current_exp': self.current_exp,
            'total_exp': self.total_exp,
            'exp_to_next_level': self.exp_to_next_level(),
            'attack_power': self.attack_power,
            'last_levelup': self.last_levelup.isoformat() if self.last_levelup else None
        }

class BossAttack(db.model):
    __tablename__ = 'boss_attacks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    boss_id = db.Column(db.Integer, db.ForeignKey('bosses.id'), nullable=False)

    steps_used = db.Column(db.Integer, nullable=False)
    damage_dealt = db.Column(db.Integer, nullable=False)
    exp_gained = db.Column(db.Integer, default=0)
    attacked_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='boss_attacks')
    boss = db.relationship('Boss', backref='attacks')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'boss_id': self.boss_id,
            'steps_used': self.steps_used,
            'damage_dealt': self.damage_dealt,
            'exp_gained': self.exp_gained,
            'attacked_at': self.attacked_at.isoformat()
        }

class BossManager(db.Model):
    @staticmethod
    def attack_boss(user, boss_id, steps_to_use):
        boss = Boss.query.get(boss_id)
        if not boss or boss.is_active or boss.is_defeated():
            return {'error': 'Boss not available for attack'}

        user_level = UserLevel.query.filter_by(user_id=user.id).first()
        if not user_level:
            user_level = UserLevel(user_id=user.id)
            db.session.add(user_level)
            db.session.commit()

        base_damage = steps_to_use
        damage_multiplier = user_level.attack_power
        total_damage = steps_to_use * damage_multiplier
        boss_defeated = boss.take_damage(total_damage)
        exp = boss.exp_reward if boss_defeated else 0
        attack = BossAttack(
            user_id=user.id,
            boss_id=boss.id,
            steps_used=steps_to_use,
            damage_dealt=total_damage,
            exp_gained=exp
        )
        db.session.add(attack)
        level_ups = user_level.add_exp(exp)
        db.session.commit()
        result = {
            'success': True,
            'damage_dealt': total_damage,
            'exp_gained': exp,
            'boss_defeated': boss_defeated,
            'level_ups': level_ups,
            'user_level': user_level.to_dict(),
            'boss_status': boss.to_dict()
        }
        if boss_defeated:
            result['boss_rewards'] = BossManager.handle_boss_defeat(boss, user)
            if boss.boss_type == 'Global' and boss.respawn_hours > 0:
                BossManager.schedule_boss_respawn(boss)

        return result

    @staticmethod
    def schedule_boss_respawn(boss):
        respawn_time = datetime.utcnow() + datetime.timedelta(hours=boss.respawn_hours)

    @staticmethod
    def handle_boss_defeat(boss, defeating_user):
        rewards = {
            'exp_reward': boss.exp_reward,
            'coin_reward': boss.coin_reward,
            'special_reward': boss.special_reward
        }
        if boss.special_reward:
            # add in boss specific rewards later
            pass
        return rewards

    @staticmethod
    def spawn_daily_bosses():
        today = date.today()
        daily_boss = Boss.query.filter_by(boss_type='Daily', is_active=True).filter(db.func.date(Boss.spawned_at) == today).first()
        if not daily_boss:
            import random
            daily_bosses = DAILY_BOSS_TEMPLATES
            template = random.choice(daily_bosses)
            new_boss = Boss(
                name=template['name'],
                description=template['description'],
                max_health=template['health'],
                current_health=template['health'],
                exp_reward=template['exp_reward'],
                boss_type='Daily',
                difficulty='Daily'
            )
            db.session.add(new_boss)
            db.session.commit()

    @staticmethod
    def get_available_bosses(user_id=None, journey_id=None):
        query = Boss.query.filter(Boss.is_active==True, Boss.current_health > 0)
        if journey_id:
            query = query.filter((Boss.journey_id == journey_id) | (Boss.boss_type == 'Global'))
        else:
            query = query.filter(Boss.boss_type.in_(['Global', 'Daily']))
        return query.all()


class Friendship(db.Model):
    __tablename__ = 'friendships'
    id = db.Column(db.Integer, primary_key=True)

    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')

    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')

    __table_args__ = (UniqueConstraint('sender_id', 'receiver_id', name='unique_friendship'))

    def __repr__(self):
        return f'Friendship from {self.sender_id} to {self.receiver_id} ({self.status})'

class Achievement(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='general')

    criteria_type = db.Column(db.String(50), nullable=False)
    criteria_value = db.Column(db.Integer, nullable=False)

    rarity = db.Column(db.String(20), default='common')
    points_value = db.Column(db.Integer, default=10)
    is_secret = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'Achievement {self.name}'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'rarity': self.rarity,
            'points_value': self.points_value,
            'is_secret': self.is_secret
        }

class UserAchievement(db.Model):
    __tablename__ = 'user_achievements'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievements.id'), nullable=False)

    earned_at = db.Column(db.DateTime, default=datetime.utcnow)
    progress = db.Column(db.Float, default=1.0)
    user = db.relationship('User', backref='earned_achievements')
    achievement = db.relationship('Achievement', backref='earned_by_users')

    __table_args__ = (UniqueConstraint('user_id', 'achievement_id', name='unique_user_achievement'))

    def __repr__(self):
        return f'UserAchievement {self.user}: {self.achievement}'



DAILY_BOSS_TEMPLATES = [
    {
        'name': 'Shadow Walker',
        'description': 'A mysterious figure that feeds on inactivity. Defeat it with your daily steps!',
        'emoji': '👤',
        'health': 10000,
        'exp_reward': 500
    },
    {
        'name': 'Couch Demon',
        'description': 'This lazy demon wants you to stay seated all day. Show it who\'s boss!',
        'emoji': '😈',
        'health': 8000,
        'exp_reward': 400
    },
    {
        'name': 'Procrastination Beast',
        'description': 'It grows stronger the longer you wait. Attack now!',
        'emoji': '🐉',
        'health': 12000,
        'exp_reward': 600
    }
]

JOURNEY_BOSS_TEMPLATES = {
    'New York City': {
        'name': 'Traffic Monster',
        'description': 'A beast born from NYC gridlock. Only walking can tame it!',
        'emoji': '🚗',
        'health': 25000,
        'exp_reward': 1000
    },
    'Los Angeles': {
        'name': 'Smog Giant',
        'description': 'Clear the air with your steps!',
        'emoji': '🌫️',
        'health': 30000,
        'exp_reward': 1200
    }
}

LEGENDARY_BOSSES = [
    {
        'name': 'The Sedentary King',
        'description': 'The ultimate enemy of all walkers. A legendary challenge!',
        'emoji': '👑',
        'health': 1000000,  # 1 million steps needed!
        'exp_reward': 10000,
        'difficulty': 'Legendary'
    }
]