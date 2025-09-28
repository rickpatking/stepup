import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    JWT_SECRET_KEY = SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)

    API_TITLE = "StepUp API"
    API_VERSION = "v1"

    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 100
    STEPS_PER_MILE = 2000
    RATE_LIMIT = 100

    MAX_CONTENT_LENGTH = 16*1024*1024
    UPLOAD_FOLDER = 'static/avatars'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_ECHO = True
    CORS_ORIGINS = ['http://localhost:3000', 'http://localhost:8081']

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    LOG_LEVEL = 'INFO'

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    return config[os.getenv('FLASK_ENV', 'default')]

def load_config(app):
    env = os.getenv('FLASK_ENV', 'development')
    config_class = config.get(env, DevelopmentConfig)
    app.config.from_object(config_class)

    if os.getenv('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    if os.getenv('DATABASE_URL'):
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

    print(f'Loaded {env} config')
    return app.config

BADGE_MILESTONES = {
    1000: {
        'name': 'First Steps',
        'description': 'Took your first 1,000 steps!',
    },
    10000: {
        'name': 'Getting Started',
        'description': 'Reached 10,000 steps!',
    },
    50000: {
        'name': 'Walking Warrior',
        'description': 'Conquered 50,000 steps!',
    },
    100000: {
        'name': 'Step Master',
        'description': 'Mastered 100,000 steps!',
    },
    500000: {
        'name': 'Marathon Legend',
        'description': 'Legendary 500,000 steps!',
    },
    1000000: {
        'name': 'Ultra Walker',
        'description': 'Ultimate achievement: 1 million steps!',
    }
}

PRESET_JOURNEYS = [
    {
        'start_city': 'New York City',
        'end_city': 'Los Angeles',
        'total_distance_miles': 2789.0,
        'description': 'Coast to coast across America!',
        'difficulty': 'Hard'
    },
    {
        'start_city': 'San Francisco',
        'end_city': 'Miami',
        'total_distance_miles': 2734.0,
        'description': 'From the Golden Gate to South Beach!',
        'difficulty': 'Hard'
    },
    {
        'start_city': 'Seattle',
        'end_city': 'Boston',
        'total_distance_miles': 3043.0,
        'description': 'From the Space Needle to Fenway Park!',
        'difficulty': 'Epic'
    },
    {
        'start_city': 'Chicago',
        'end_city': 'Las Vegas',
        'total_distance_miles': 1747.0,
        'description': 'From the Windy City to Sin City!',
        'difficulty': 'Medium'
    },
    {
        'start_city': 'London',
        'end_city': 'Rome',
        'total_distance_miles': 1434.0,
        'description': 'From Big Ben to the Colosseum!',
        'difficulty': 'Medium'
    },
    {
        'start_city': 'Denver',
        'end_city': 'Austin',
        'total_distance_miles': 877.0,
        'description': 'Rocky Mountain high to Texas charm!',
        'difficulty': 'Easy'
    }
]