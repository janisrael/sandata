"""
Configuration file for Security Tester
Manages app settings, security, rate limits, and async tasks
"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    
    # Flask Core
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///security_tester.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = True  # HTTPS only (disable for local dev)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL') or os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_HEADERS_ENABLED = True
    
    # Rate limit tiers
    RATE_LIMIT_GUEST = "2 per minute, 10 per hour"  # For non-authenticated users
    RATE_LIMIT_USER = "5 per minute, 50 per hour"   # For regular users
    RATE_LIMIT_ADMIN = "20 per minute, 200 per hour"  # For admins
    
    # Celery (Async Tasks)
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/1'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/2'
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 300  # 5 minutes max per task
    
    # Security Settings
    MAX_SCAN_TIMEOUT = 120  # Max scan duration in seconds
    ALLOWED_SCAN_PROTOCOLS = ['http://', 'https://']
    
    # Roles
    ROLES = {
        'guest': 0,
        'user': 1,
        'admin': 2
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False  # Allow HTTP for local dev

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    # In production, ensure these are set via environment variables:
    # SECRET_KEY, DATABASE_URL, REDIS_URL

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    # Use memory storage for rate limiting in tests (no Redis needed)
    RATELIMIT_STORAGE_URL = 'memory://'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

