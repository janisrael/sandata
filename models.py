"""
Database models for Security Tester
User authentication, roles, and scan history
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # guest, user, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    scans = db.relationship('ScanHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Verify password"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    @property
    def is_regular_user(self):
        """Check if user is regular user"""
        return self.role == 'user'
    
    def get_rate_limit(self):
        """Get rate limit based on role"""
        from config import Config
        if self.role == 'admin':
            return Config.RATE_LIMIT_ADMIN
        elif self.role == 'user':
            return Config.RATE_LIMIT_USER
        else:
            return Config.RATE_LIMIT_GUEST
    
    def __repr__(self):
        return f'<User {self.username}>'


class ScanHistory(db.Model):
    """Scan history with user association"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, index=True)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for backward compatibility
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # general, payment
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    score = db.Column(db.Integer)
    findings_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    result_data = db.Column(db.Text)  # JSON string of full results
    
    def __repr__(self):
        return f'<ScanHistory {self.scan_id}>'
    
    @property
    def duration(self):
        """Calculate scan duration"""
        if self.completed_at and self.created_at:
            return (self.completed_at - self.created_at).total_seconds()
        return None


def init_db(app):
    """Initialize database"""
    db.init_app(app)
    bcrypt.init_app(app)
    
    with app.app_context():
        try:
            # Create tables if they don't exist (create_all is idempotent)
            # But handle the case where tables already exist due to persistent volume
            db.create_all()
        except Exception as e:
            # If there's an error (like table already exists), try to verify tables are accessible
            import logging
            logging.warning(f"Database initialization warning: {e}")
            try:
                # Try to query a table to verify database is accessible
                User.query.limit(1).all()
            except Exception as verify_error:
                # If we can't access tables, re-raise the original error
                raise e from verify_error
        
        # Create default admin user if not exists
        # Handle race conditions where multiple workers try to create admin simultaneously
        admin_email = app.config.get('ADMIN_EMAIL', 'admin@example.com')
        admin_password = app.config.get('ADMIN_PASSWORD', 'admin123')
        
        try:
            # Check if admin exists first
            admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                # Double-check by username as well (race condition protection)
                admin = User.query.filter_by(username='admin').first()
                if not admin:
                    try:
                        admin = User(
                            username='admin',
                            email=admin_email,
                            role='admin'
                        )
                        admin.set_password(admin_password)
                        db.session.add(admin)
                        db.session.commit()
                        print(f"✅ Created admin user: {admin_email}")
                    except Exception as create_error:
                        # Handle race condition - another worker might have created it
                        db.session.rollback()
                        # Verify it was created by another worker
                        admin = User.query.filter_by(email=admin_email).first()
                        if admin:
                            print(f"ℹ️ Admin user created by another worker: {admin_email}")
                        else:
                            import logging
                            logging.warning(f"Could not create admin user: {create_error}")
                else:
                    print(f"ℹ️ Admin user already exists (by username): {admin_email}")
            else:
                print(f"ℹ️ Admin user already exists: {admin_email}")
        except Exception as e:
            # Final fallback - just log and continue
            import logging
            logging.warning(f"Error during admin user initialization: {e}")
            db.session.rollback()
            # Don't crash the app - admin might already exist
            print(f"⚠️ Admin user initialization had issues, but continuing...")

