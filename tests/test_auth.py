"""
Unit tests for authentication system
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
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

@pytest.fixture
def test_user(client):
    """Create a test user"""
    with app.app_context():
        user = User(username='testuser', email='test@example.com', role='user')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        return user

def test_register(client):
    """Test user registration"""
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'password123',
        'confirm_password': 'password123'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    
    # Check user was created
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not none
        assert user.email == 'newuser@example.com'

def test_login(client, test_user):
    """Test user login"""
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)
    
    assert response.status_code == 200

def test_login_invalid_credentials(client, test_user):
    """Test login with invalid credentials"""
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    
    assert b'Invalid email or password' in response.data or response.status_code == 200

def test_password_hashing(client):
    """Test password hashing"""
    with app.app_context():
        user = User(username='hashtest', email='hash@example.com')
        user.set_password('testpassword')
        
        assert user.password_hash != 'testpassword'
        assert user.check_password('testpassword')
        assert not user.check_password('wrongpassword')

def test_protected_route_requires_login(client):
    """Test that protected routes require authentication"""
    response = client.get('/dashboard')
    assert response.status_code == 302  # Redirect to login

def test_logout(client, test_user):
    """Test user logout"""
    # Login first
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    # Then logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200

