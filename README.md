# Sandata — Professional Security Assessment Platform

A **production-ready** Flask application that performs safe, authorized security checks on websites and payment pages. Professional security assessment tool featuring authentication, role-based access control, rate limiting, and asynchronous scanning.

> **Deployment**: Automated CI/CD via GitHub Actions | Last updated: 2025-11-22

> **⚠️ IMPORTANT LEGAL & ETHICAL NOTICE:** Use this tool **ONLY** on systems you own or where you have explicit written permission to test. Unauthorized scanning is **illegal and unethical**.

## 🚀 What's New in v2.0

### Phase 1 Production Features
- ✅ **User Authentication** - Secure login/registration system with password hashing
- ✅ **Role-Based Access Control (RBAC)** - Admin, User, and Guest roles
- ✅ **Rate Limiting** - Configurable limits per role (5/min, 50/hour for users)
- ✅ **Async Scanning** - Celery + Redis for background job processing
- ✅ **Real-time Progress** - Track scan status in real-time
- ✅ **User Dashboard** - Personal scan history and statistics
- ✅ **Admin Panel** - User management and system monitoring
- ✅ **Testing Suite** - Comprehensive unit and integration tests
- ✅ **Enhanced Security** - CSRF protection, session management, secure cookies

## Features

### Security Scanning Capabilities

#### General Security Scan (22 Tests)
1. HTTP Security Headers validation (CSP, X-Frame-Options, HSTS, etc.)
2. TLS/SSL Certificate inspection and expiry checks
3. Cookie Security flags analysis (HttpOnly, Secure, SameSite)
4. Reflected Input detection (XSS risk identification)
5. Critical Files Exposure checks (.htaccess, .env, .git/config, backups)
6. Common Files/Endpoints exposure
7. CMS Detection (WordPress, Joomla)
8. Server Version exposure analysis

#### Payment Page Security Scan (14 Specialized Tests)
1. HTTPS Enforcement validation
2. Mixed Content detection
3. Payment Form security analysis
4. PCI DSS Compliance indicators
5. Payment Gateway detection (Stripe, PayPal, Square, etc.)
6. CSRF Token validation
7. reCAPTCHA/CAPTCHA detection (Google, hCaptcha, Turnstile)
8. HTML5 Form Validation analysis
9. .htaccess File exposure check
10. TLS 1.2+ requirement verification
11. Cipher Strength analysis
12. Credit Card Field security
13. Autocomplete security settings
14. Bot Protection validation

### User Management & Security
- **Authentication System** - Secure login with bcrypt password hashing
- **User Roles** - Admin, User, Guest with different privileges
- **Session Management** - Secure 2-hour sessions with HttpOnly cookies
- **Rate Limiting** - Prevent abuse with per-role limits
- **CSRF Protection** - WTForms CSRF tokens on all forms

### UI/UX Features
- Beautiful **Neumorphism UI** design
- Responsive design for all devices
- User Dashboard with scan history
- Admin Panel for system management
- Real-time scan progress tracking
- Detailed reports with step-by-step remediation
- JSON export functionality

## Installation

### Prerequisites
- Python 3.8 or higher
- Redis server (for Celery and rate limiting)
- pip (Python package manager)

### Quick Start

1. **Clone or navigate to the project directory:**
```bash
cd /path/to/security_tester
```

2. **Create a virtual environment (recommended):**
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Install and start Redis:**

**On Ubuntu/Debian:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

**On macOS (with Homebrew):**
```bash
brew install redis
brew services start redis
```

**On Windows:**
Download from https://github.com/microsoftarchive/redis/releases

**Using Docker:**
```bash
docker run -d -p 6379:6379 redis:latest
```

5. **Set up environment variables:**
```bash
# Copy the example file
cp .env.example .env

# Edit .env and set your configuration
nano .env  # or use your preferred editor
```

6. **Initialize the database:**
```bash
# The database will be created automatically on first run
# Default admin account will be created:
# Email: admin@example.com
# Password: admin123
# (Change these in .env before first run!)
```

7. **Run the Flask application:**
```bash
PORT=4444 python app.py
```

8. **Start Celery worker (in a new terminal):**
```bash
# Activate virtual environment first
source venv/bin/activate

# Start Celery worker
celery -A celery_worker.celery worker --loglevel=info
```

9. **Access the application:**
Open your browser and navigate to:
```
http://localhost:4444
```

## Configuration

### Environment Variables

Create a `.env` file in the project root (see `.env.example`):

```env
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-change-this
PORT=4444

# Database
DATABASE_URL=sqlite:///security_tester.db

# Redis (for rate limiting and Celery)
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# Admin Account (created on first run)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme123
```

### Rate Limiting Configuration

Edit `config.py` to adjust rate limits:

```python
RATE_LIMIT_GUEST = "2 per minute, 10 per hour"
RATE_LIMIT_USER = "5 per minute, 50 per hour"
RATE_LIMIT_ADMIN = "20 per minute, 200 per hour"
```

## Usage

### For End Users

1. **Register an Account**
   - Navigate to `/register`
   - Create your account with username, email, and password
   - Login automatically after registration

2. **Start a Scan**
   - Enter target URL (must start with `http://` or `https://`)
   - Select scan type (General or Payment Page)
   - Click "Start Scan"
   - Monitor progress in real-time

3. **View Results**
   - Access your dashboard at `/dashboard`
   - Review scan history
   - Click on any scan to view detailed report
   - Export results as JSON

4. **Security Tests Documentation**
   - Visit `/security_list` to see all 22 security tests
   - Understand what each test checks
   - Learn about the scoring system

### For Administrators

1. **Access Admin Panel**
   - Login with admin account
   - Navigate to `/admin`

2. **Manage Users**
   - View all registered users
   - Monitor user activity
   - Check scan statistics

3. **System Monitoring**
   - View all system scans
   - Monitor rate limiting effectiveness
   - Track system health

## API Documentation

All API endpoints require authentication (except `/api/health`).

### Authentication

```bash
# Login to get session cookie
curl -X POST http://localhost:4444/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com&password=yourpassword" \
  -c cookies.txt

# Use session cookie for API requests
curl -b cookies.txt http://localhost:4444/api/results
```

### Endpoints

#### `POST /api/scan`
Start a general security scan (rate limited).

**Request:**
```json
{
  "target": "https://example.com",
  "async": true,
  "options": {}
}
```

**Response:**
```json
{
  "status": "queued",
  "result_id": "uuid",
  "task_id": "celery-task-id",
  "message": "Scan queued successfully"
}
```

#### `POST /api/scan/payment`
Start a payment page security scan (rate limited).

**Request:**
```json
{
  "target": "https://example.com/checkout",
  "async": true
}
```

#### `GET /api/task/<task_id>`
Get async task status and progress.

**Response:**
```json
{
  "state": "PROGRESS",
  "status": "Running payment security scan..."
}
```

#### `GET /api/results`
List all your scan results (admin sees all scans).

#### `GET /api/results/<result_id>`
Get specific scan result details.

#### `GET /api/health`
Health check endpoint (no authentication required).

**Response:**
```json
{
  "status": "ok",
  "version": "2.0",
  "features": {
    "authentication": true,
    "rate_limiting": true,
    "async_scanning": true
  }
}
```

## Testing

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_auth.py

# Run with verbose output
pytest -v
```

### Test Coverage

The test suite includes:
- Authentication tests (login, register, logout, password hashing)
- Scanning functionality tests
- Rate limiting tests
- API endpoint tests
- RBAC tests

## Project Structure

```
security_tester/
├── app.py                      # Main Flask application with auth & rate limiting
├── config.py                   # Configuration management
├── models.py                   # Database models (User, ScanHistory)
├── forms.py                    # WTForms for authentication
├── tasks.py                    # Celery async tasks
├── celery_worker.py            # Celery configuration
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
├── .env.example               # Environment variables template
├── scanner/
│   ├── __init__.py
│   ├── scanner.py             # General security scanner
│   ├── payment_scanner.py     # Payment page scanner
│   └── db.py                  # Legacy database helper
├── templates/
│   ├── index.html             # Main scanner interface
│   ├── security_list.html     # Security tests documentation
│   ├── login.html             # Login page
│   ├── register.html          # Registration page
│   ├── dashboard.html         # User dashboard
│   ├── admin.html             # Admin panel
│   ├── 404.html               # Error page
│   └── 500.html               # Error page
├── static/
│   ├── style.css              # Neumorphism UI (1500+ lines)
│   └── app.js                 # Frontend JavaScript
└── tests/
    ├── __init__.py
    ├── test_auth.py           # Authentication tests
    ├── test_scanning.py       # Scanning tests
    └── test_rate_limiting.py  # Rate limiting tests
```

## Security Best Practices

### What This Tool DOES
✓ Observational security checks  
✓ Header and TLS analysis  
✓ Form security validation  
✓ Safe reflection tests  
✓ Common file enumeration  
✓ Security configuration review  

### What This Tool DOES NOT DO
✗ Exploit vulnerabilities  
✗ Brute force attacks  
✗ SQL injection exploitation  
✗ Remote code execution  
✗ DDoS testing  
✗ Password cracking  
✗ Aggressive port scanning  

## Production Deployment

### Security Checklist

Before deploying to production:

1. ✅ Change `SECRET_KEY` to a strong random value
2. ✅ Update admin credentials
3. ✅ Set `FLASK_ENV=production`
4. ✅ Enable `SESSION_COOKIE_SECURE=True` (requires HTTPS)
5. ✅ Use PostgreSQL instead of SQLite
6. ✅ Set up proper Redis persistence
7. ✅ Configure firewall rules
8. ✅ Set up SSL/TLS certificates
9. ✅ Enable logging and monitoring
10. ✅ Regular backup strategy

### Recommended Stack

- **Web Server**: Nginx or Apache
- **WSGI**: Gunicorn or uWSGI
- **Database**: PostgreSQL
- **Cache/Queue**: Redis (persistent)
- **Process Manager**: Supervisor or systemd
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK Stack or CloudWatch

### Docker Deployment (Optional)

```bash
# Coming soon - Docker Compose setup for easy deployment
```

## Troubleshooting

### Common Issues

**Issue**: `Connection refused` to Redis  
**Solution**: Ensure Redis is running: `redis-cli ping` should return `PONG`

**Issue**: Celery worker not starting  
**Solution**: Check Redis connection and ensure Celery is installed

**Issue**: Rate limit errors  
**Solution**: Wait for the rate limit window to reset or adjust limits in `config.py`

**Issue**: `ModuleNotFoundError`  
**Solution**: Install all dependencies: `pip install -r requirements.txt`

**Issue**: Database errors  
**Solution**: Delete `security_tester.db` and restart app to recreate

## Contributing

Improvements welcome! Consider adding:
- OAuth2 authentication (Google, GitHub)
- Two-factor authentication (2FA)
- PDF report generation
- Email notifications
- Webhook integrations
- More security tests
- Docker Compose setup
- CI/CD pipeline

## License & Disclaimer

This tool is provided for **educational and authorized testing purposes only**. The developers assume no liability for misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization.

**Always:**
- Get written permission before scanning
- Follow responsible disclosure practices
- Comply with applicable laws
- Respect privacy and data protection regulations

---

## Credits

**Created By**: Jan Francis Israel  
**Website**: https://janisrael.com  
**HuggingFace**: https://huggingface.co/swordfish7412  
**GitHub**: https://github.com/janisrael

---

**Project**: Sandata  
**Version**: 2.0  
**Status**: Production Ready  
**Last Updated**: November 2025

---

**Remember: Use this tool responsibly and only on systems you own or have explicit permission to test!** 🔒
