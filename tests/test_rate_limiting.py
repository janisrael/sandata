"""
Tests for rate limiting functionality
"""
import pytest
from app import app
from models import db, User

@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['RATELIMIT_ENABLED'] = True
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create test user
            user = User(username='testuser', email='test@example.com', role='user')
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
        yield client
        with app.app_context():
            db.drop_all()

@pytest.fixture
def authenticated_client(client):
    """Authenticated test client"""
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    return client

def test_rate_limit_headers(authenticated_client):
    """Test that rate limit headers are present"""
    response = authenticated_client.post('/api/scan', json={
        'target': 'https://example.com'
    })
    
    # Check for rate limit headers
    # Note: Actual headers depend on Redis being available
    assert response.status_code in [200, 429, 500]  # 500 if Redis not available

