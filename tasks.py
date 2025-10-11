"""
Celery tasks for async scanning
"""
from celery_worker import celery
from scanner.scanner import run_scan
from scanner.payment_scanner import run_payment_scan
from models import db, ScanHistory
from datetime import datetime
import json

@celery.task(bind=True, name='tasks.async_scan')
def async_scan(self, target, scan_type='general', options=None, user_id=None):
    """
    Async task for running security scans
    
    Args:
        target: URL to scan
        scan_type: 'general' or 'payment'
        options: Additional scan options
        user_id: User ID who initiated the scan
    
    Returns:
        dict: Scan results
    """
    options = options or {}
    
    # Update task state to STARTED
    self.update_state(state='STARTED', meta={'status': 'Initializing scan...'})
    
    try:
        # Run appropriate scanner
        if scan_type == 'payment':
            self.update_state(state='PROGRESS', meta={'status': 'Running payment security scan...'})
            result = run_payment_scan(target, options)
        else:
            self.update_state(state='PROGRESS', meta={'status': 'Running general security scan...'})
            result = run_scan(target, options)
        
        # Save to database
        self.update_state(state='PROGRESS', meta={'status': 'Saving results...'})
        
        scan_history = ScanHistory.query.filter_by(scan_id=result['id']).first()
        if scan_history:
            scan_history.status = 'completed'
            scan_history.completed_at = datetime.utcnow()
            scan_history.score = result.get('score', 0)
            scan_history.findings_count = len(result.get('findings', []))
            scan_history.result_data = json.dumps(result)
            db.session.commit()
        
        self.update_state(state='SUCCESS', meta={'status': 'Scan completed', 'result_id': result['id']})
        
        return {
            'status': 'success',
            'result_id': result['id'],
            'score': result.get('score', 0),
            'findings_count': len(result.get('findings', []))
        }
        
    except Exception as e:
        # Update scan history on failure
        self.update_state(state='FAILURE', meta={'status': f'Scan failed: {str(e)}'})
        raise

@celery.task(name='tasks.cleanup_old_scans')
def cleanup_old_scans(days=30):
    """
    Cleanup scans older than specified days
    
    Args:
        days: Number of days to keep scans
    """
    from datetime import timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    old_scans = ScanHistory.query.filter(ScanHistory.created_at < cutoff_date).all()
    count = len(old_scans)
    
    for scan in old_scans:
        db.session.delete(scan)
    
    db.session.commit()
    
    return f'Cleaned up {count} old scans'

