"""
Unit tests for scanning functionality
"""
import pytest
from unittest.mock import patch, MagicMock
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
            # Create test user
            user = User(username='testuser', email='test@example.com', role='user')
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
        yield client
        with app.app_context():
            db.session.remove()
            db.drop_all()

@pytest.fixture
def authenticated_client(client):
    """Authenticated test client"""
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    return client

def test_scan_requires_authentication(client):
    """Test that scan endpoint requires authentication"""
    response = client.post('/api/scan', json={
        'target': 'https://example.com'
    })
    assert response.status_code == 401  # Unauthorized

def test_scan_invalid_url(authenticated_client):
    """Test scan with invalid URL"""
    response = authenticated_client.post('/api/scan', json={
        'target': 'not-a-url'
    })
    assert response.status_code == 400

def test_scan_missing_target(authenticated_client):
    """Test scan without target"""
    response = authenticated_client.post('/api/scan', json={})
    assert response.status_code == 400

@patch('scanner.scanner.run_scan')
def test_scan_success(mock_run_scan, authenticated_client):
    """Test successful scan"""
    mock_run_scan.return_value = {
        'id': 'test-scan-id',
        'target': 'https://example.com',
        'score': 85,
        'findings': []
    }
    
    response = authenticated_client.post('/api/scan', json={
        'target': 'https://example.com',
        'async': False
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert 'result_id' in data

def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'ok'
    assert 'version' in data

