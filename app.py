"""
Sandata - Professional Security Assessment Platform
Enhanced with Authentication, Rate Limiting, and Async Scanning
"""
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash
import os
import json
from datetime import datetime

# Local imports
from config import config
from models import db, bcrypt, User, ScanHistory, init_db
from forms import LoginForm, RegisterForm, ChangePasswordForm
from celery_worker import make_celery
from scanner.scanner import run_scan
from scanner.payment_scanner import run_payment_scan

# Initialize Flask app
app = Flask(__name__)

# Load configuration
env = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[env])

# Initialize extensions
init_db(app)
bcrypt.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'info'

# Initialize Celery
celery = make_celery(app)

# Initialize Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URL'],
    default_limits=[]  # We'll apply limits per route
)

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.query.get(int(user_id))

def get_rate_limit():
    """Get rate limit based on user role"""
    if current_user.is_authenticated:
        return current_user.get_rate_limit()
    return app.config['RATE_LIMIT_GUEST']

# ============= PUBLIC ROUTES =============

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/security_list')
def security_list():
    """Security tests documentation"""
    return render_template('security_list.html')

# ============= AUTHENTICATION ROUTES =============

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Contact admin.', 'error')
                return redirect(url_for('login'))
            
            login_user(user, remember=form.remember_me.data)
            user.update_last_login()
            
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role='user'
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'Account created successfully! Welcome, {user.username}!', 'success')
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get user's recent scans
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id)\
        .order_by(ScanHistory.created_at.desc())\
        .limit(10).all()
    
    # Get statistics
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    
    return render_template('dashboard.html', 
                         recent_scans=recent_scans,
                         total_scans=total_scans)

# ============= ADMIN ROUTES =============

@app.route('/admin')
@login_required
def admin_panel():
    """Admin panel"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Get scan statistics
    total_scans = ScanHistory.query.count()
    recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(20).all()
    
    return render_template('admin.html', 
                         users=users,
                         total_scans=total_scans,
                         recent_scans=recent_scans)

# ============= SCAN API ENDPOINTS =============

@app.route('/api/scan', methods=['POST'])
@limiter.limit(get_rate_limit)
@login_required
def api_scan():
    """General security scan endpoint with rate limiting"""
    data = request.json or {}
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'target required'}), 400
    
    # Validate URL format
    if not target.startswith('http://') and not target.startswith('https://'):
        return jsonify({'error': 'target must start with http:// or https://'}), 400
    
    try:
        # Check if async is requested
        use_async = data.get('async', True)
        
        if use_async and celery:
            # Queue async task
            from tasks import async_scan
            import uuid
            
            scan_id = str(uuid.uuid4())
            
            # Create scan history entry
            scan_history = ScanHistory(
                scan_id=scan_id,
                user_id=current_user.id,
                target_url=target,
                scan_type='general',
                status='pending'
            )
            db.session.add(scan_history)
            db.session.commit()
            
            # Queue task
            task = async_scan.delay(target, 'general', data.get('options', {}), current_user.id)
            
            return jsonify({
                'status': 'queued',
                'result_id': scan_id,
                'task_id': task.id,
                'message': 'Scan queued successfully'
            })
        else:
            # Run synchronously (for backwards compatibility)
            result = run_scan(target, options=data.get('options', {}))
            
            # Ensure result has required fields
            if 'details' not in result:
                result['details'] = result.copy()
            if 'findings' not in result.get('details', {}):
                result['details']['findings'] = result.get('findings', [])
            
            # Save to database
            scan_history = ScanHistory(
                scan_id=result['id'],
                user_id=current_user.id,
                target_url=target,
                scan_type='general',
                status='completed',
                completed_at=datetime.utcnow(),
                score=result.get('score', 0),
                findings_count=len(result.get('details', {}).get('findings', [])),
                result_data=json.dumps(result)
            )
            db.session.add(scan_history)
            db.session.commit()
            
            return jsonify({'status': 'done', 'result_id': result['id']})
            
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/api/scan/payment', methods=['POST'])
@limiter.limit(get_rate_limit)
@login_required
def api_payment_scan():
    """Payment page security scan endpoint with rate limiting"""
    data = request.json or {}
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'target required'}), 400
    
    # Validate URL format
    if not target.startswith('http://') and not target.startswith('https://'):
        return jsonify({'error': 'target must start with http:// or https://'}), 400
    
    try:
        # Check if async is requested
        use_async = data.get('async', True)
        
        if use_async and celery:
            # Queue async task
            from tasks import async_scan
            import uuid
            
            scan_id = str(uuid.uuid4())
            
            # Create scan history entry
            scan_history = ScanHistory(
                scan_id=scan_id,
                user_id=current_user.id,
                target_url=target,
                scan_type='payment',
                status='pending'
            )
            db.session.add(scan_history)
            db.session.commit()
            
            # Queue task
            task = async_scan.delay(target, 'payment', data.get('options', {}), current_user.id)
            
            return jsonify({
                'status': 'queued',
                'result_id': scan_id,
                'task_id': task.id,
                'message': 'Scan queued successfully'
            })
        else:
            # Run synchronously
            result = run_payment_scan(target, options=data.get('options', {}))
            
            # Ensure result has required fields
            if 'details' not in result:
                result['details'] = result.copy()
            if 'findings' not in result.get('details', {}):
                result['details']['findings'] = result.get('findings', [])
            
            # Save to database
            scan_history = ScanHistory(
                scan_id=result['id'],
                user_id=current_user.id,
                target_url=target,
                scan_type='payment',
                status='completed',
                completed_at=datetime.utcnow(),
                score=result.get('score', 0),
                findings_count=len(result.get('details', {}).get('findings', [])),
                result_data=json.dumps(result)
            )
            db.session.add(scan_history)
            db.session.commit()
            
            return jsonify({'status': 'done', 'result_id': result['id']})
            
    except Exception as e:
        return jsonify({'error': f'Payment scan failed: {str(e)}'}), 500

@app.route('/api/task/<task_id>')
@login_required
def api_task_status(task_id):
    """Get async task status"""
    from celery.result import AsyncResult
    task = AsyncResult(task_id, app=celery)
    
    if task.state == 'PENDING':
        response = {
            'state': task.state,
            'status': 'Task is waiting...'
        }
    elif task.state == 'STARTED':
        response = {
            'state': task.state,
            'status': task.info.get('status', 'Task started')
        }
    elif task.state == 'PROGRESS':
        response = {
            'state': task.state,
            'status': task.info.get('status', 'In progress...')
        }
    elif task.state == 'SUCCESS':
        response = {
            'state': task.state,
            'status': 'Completed',
            'result': task.info
        }
    else:  # FAILURE or other states
        response = {
            'state': task.state,
            'status': str(task.info)
        }
    
    return jsonify(response)

@app.route('/api/results')
@login_required
def api_results():
    """List user's scan results"""
    if current_user.is_admin:
        # Admin can see all scans
        scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    else:
        # Regular users see only their scans
        scans = ScanHistory.query.filter_by(user_id=current_user.id)\
            .order_by(ScanHistory.created_at.desc()).all()
    
    results = []
    for scan in scans:
        results.append({
            'id': scan.scan_id,
            'target': scan.target_url,
            'type': scan.scan_type,
            'status': scan.status,
            'score': scan.score,
            'findings_count': scan.findings_count,
            'timestamp': scan.created_at.isoformat(),
            'user': scan.user.username if scan.user else 'Anonymous'
        })
    
    return jsonify(results)

@app.route('/api/results/<rid>')
@login_required
def api_result(rid):
    """Get specific scan result"""
    scan = ScanHistory.query.filter_by(scan_id=rid).first()
    
    if not scan:
        return jsonify({'error': 'not found'}), 404
    
    # Check permissions
    if not current_user.is_admin and scan.user_id != current_user.id:
        return jsonify({'error': 'access denied'}), 403
    
    if scan.result_data:
        result = json.loads(scan.result_data)
        return jsonify(result)
    
    return jsonify({'error': 'result data not available'}), 404

@app.route('/api/results/<rid>', methods=['DELETE'])
@login_required
def delete_scan_result(rid):
    """Delete a specific scan result"""
    scan = ScanHistory.query.filter_by(scan_id=rid).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check permissions - user can only delete their own scans, admin can delete any
    if not current_user.is_admin and scan.user_id != current_user.id:
        return jsonify({'error': 'Access denied. You can only delete your own scans.'}), 403
    
    try:
        db.session.delete(scan)
        db.session.commit()
        return jsonify({'message': 'Scan deleted successfully', 'scan_id': rid}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete scan: {str(e)}'}), 500

@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'Sandata API is running',
        'version': '2.0',
        'features': {
            'authentication': True,
            'rate_limiting': True,
            'async_scanning': True
        }
    })

# ============= ERROR HANDLERS =============

@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429

@app.errorhandler(404)
def not_found(e):
    """Page not found"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """Internal server error"""
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'internal server error'}), 500
    return render_template('500.html'), 500

# ============= CONTEXT PROCESSORS =============

@app.context_processor
def inject_user():
    """Make current_user available in all templates"""
    return dict(current_user=current_user)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 4444))
    print(f"""
    ╔════════════════════════════════════════════════════════════╗
    ║                   Sandata v2.0 - Started                   ║
    ║          Professional Security Assessment Platform         ║
    ╠════════════════════════════════════════════════════════════╣
    ║  Server running on: http://0.0.0.0:{port}                      ║
    ║  Features: Auth ✓ | Rate Limit ✓ | Async ✓               ║
    ║  Use ONLY on systems you own or have permission to test   ║
    ║                                                            ║
    ║  Created by: Jan Francis Israel                            ║
    ║  Website: https://janisrael.com                            ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    # Note: debug=True and host='0.0.0.0' are for development only
    # In production, use a proper WSGI server (gunicorn/uwsgi) with debug=False
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)  # nosec B201, B104
