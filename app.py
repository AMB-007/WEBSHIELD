from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import os
import time
import threading
from dotenv import load_dotenv
import json
from zoneinfo import ZoneInfo

# Import ML service
from ml_service import ml_detector

# Initialize ML detection storage
ml_detections_cache = []

# check_attack_blocking is defined after the models below

load_dotenv()

try:
    DISPLAY_TIMEZONE = ZoneInfo(os.getenv('APP_TIMEZONE', 'Asia/Kolkata'))
except Exception:
    DISPLAY_TIMEZONE = timezone(timedelta(hours=5, minutes=30))


def assume_utc_timestamp(value):
    """Treat stored naive timestamps as UTC so they can be serialized/displayed correctly."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def serialize_timestamp(value):
    aware_value = assume_utc_timestamp(value)
    if aware_value is None:
        return None
    return aware_value.isoformat().replace('+00:00', 'Z')


def format_display_timestamp(value, fmt='%Y-%m-%d %H:%M:%S'):
    aware_value = assume_utc_timestamp(value)
    if aware_value is None:
        return ''
    return aware_value.astimezone(DISPLAY_TIMEZONE).strftime(fmt)


def normalize_severity(value, default='medium'):
    valid_levels = {'low', 'medium', 'high', 'critical'}
    if not value:
        return default
    normalized = str(value).strip().lower()
    return normalized if normalized in valid_levels else default


def severity_from_probability(probability):
    probability = float(probability or 0.0)
    if probability >= 0.95:
        return 'critical'
    if probability >= 0.80:
        return 'high'
    if probability >= 0.50:
        return 'medium'
    return 'low'


def get_detection_severity(detection):
    linked_severity = normalize_severity(
        getattr(getattr(detection, 'attack_log', None), 'severity', None),
        default=None
    )
    if linked_severity:
        return linked_severity

    severity = severity_from_probability(detection.probability)
    if (detection.attack_type or '').lower() == 'sql_injection' and severity in {'low', 'medium'}:
        return 'high'
    return severity

app = Flask(__name__)
CORS(app)
app.jinja_env.filters['display_time'] = format_display_timestamp

# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cybersec_logs.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    target_url = db.Column(db.String(200))
    target_host = db.Column(db.String(100))
    payload = db.Column(db.Text)
    status_code = db.Column(db.Integer)
    response_size = db.Column(db.Integer)  # Bug 1 fix: was missing, caused AttributeError/TypeError
    method = db.Column(db.String(10))
    user_agent = db.Column(db.String(500))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    raw_data = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'attack_type': self.attack_type,
            'timestamp': serialize_timestamp(self.timestamp),
            'source_ip': self.source_ip,
            'target_url': self.target_url,
            'target_host': self.target_host,
            'payload': self.payload,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'method': self.method,
            'user_agent': self.user_agent,
            'raw_data': self.raw_data,
            'severity': self.severity,
            'description': self.description
        }

# Login Attempt Model for Brute Force Tracking
class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255))  # Store hashed password attempt
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    session_id = db.Column(db.String(255))
    raw_request = db.Column(db.Text)
    # ML Detection fields
    ml_prediction = db.Column(db.Integer, nullable=True)  # 0 or 1
    ml_probability = db.Column(db.Float, nullable=True)   # 0.0 to 1.0
    ml_detected_at = db.Column(db.DateTime, nullable=True)  # When ML detected

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': serialize_timestamp(self.timestamp),
            'success': self.success,
            'session_id': self.session_id,
            'ml_prediction': self.ml_prediction,
            'ml_probability': self.ml_probability,
            'ml_detected_at': self.ml_detected_at.isoformat() if self.ml_detected_at else None
        }

# ML Detection Model
class MLDetection(db.Model):
    """Store ML detection results"""
    id = db.Column(db.Integer, primary_key=True)
    attack_log_id = db.Column(db.Integer, db.ForeignKey('attack_log.id'), nullable=True)
    login_attempt_id = db.Column(db.Integer, db.ForeignKey('login_attempt.id'), nullable=True)
    features = db.Column(db.Text)  # JSON string of features
    prediction = db.Column(db.Integer)  # 0 or 1
    probability = db.Column(db.Float)   # 0.0 to 1.0
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    attack_type = db.Column(db.String(50), default='brute_force')
    
    # Relationships
    attack_log = db.relationship('AttackLog', backref='ml_detections')
    login_attempt = db.relationship('LoginAttempt', backref='ml_detections')

    def to_dict(self):
        return {
            'id': self.id,
            'attack_log_id': self.attack_log_id,
            'login_attempt_id': self.login_attempt_id,
            'features': self.features,
            'prediction': self.prediction,
            'probability': self.probability,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'source_ip': self.source_ip,
            'attack_type': self.attack_type
        }


def check_attack_blocking():
    """Check if user should be blocked due to recent attacks"""
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    recent_attacks = MLDetection.query.filter(
        MLDetection.source_ip == request.remote_addr,
        MLDetection.detected_at >= datetime.utcnow() - timedelta(seconds=5)
    ).count()

    if recent_attacks > 0:
        session.clear()
        return render_template('login.html', error='Access blocked due to recent attack detection. Please wait 5 seconds.')

    return None

# Routes
@app.route('/')
def index():
    """Redirect to admin dashboard as default"""
    return redirect(url_for('admin_dashboard'))

@app.route('/dashboard')
def dashboard():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(50).all()
    total_logs = AttackLog.query.count()
    critical_logs = AttackLog.query.filter(
        db.func.lower(AttackLog.severity) == 'critical'
    ).count()
    unique_ips = db.session.query(AttackLog.source_ip).filter(
        AttackLog.source_ip.isnot(None)
    ).distinct().count()
    attack_types = db.session.query(AttackLog.attack_type).filter(
        AttackLog.attack_type.isnot(None)
    ).distinct().count()

    return render_template(
        'dashboard.html',
        logs=logs,
        logs_json=[log.to_dict() for log in logs],
        total_logs=total_logs,
        critical_logs=critical_logs,
        unique_ips=unique_ips,
        attack_types=attack_types,
        session_username=session.get('username')
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Enhanced login route with ML detection for both brute force and SQL injection"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        print(f"Login attempt - Username: {username}, IP: {ip_address}")
        
        # Check for SQL injection in username and password
        sql_injection_detected = False
        sql_detection_data = None
        
        if ml_detector.sql_injection_detector.is_loaded:
            # List of common legitimate usernames that should bypass ML detection
            legitimate_usernames = ['admin', 'user', 'test', 'root', 'guest', 'administrator', 'manager']
            
            # Check username for SQL injection (but bypass for common legitimate usernames)
            username_prediction, username_prob = ml_detector.sql_injection_detector.predict_sql_injection(username)
            if username_prediction == 1 and username.lower() not in legitimate_usernames:
                sql_detection_data = ml_detector.detect_sql_injection(username, ip_address)
                sql_injection_detected = True
                print(f" SQL Injection detected in username: {username} (Probability: {username_prob:.2f})")
            elif username_prediction == 1 and username.lower() in legitimate_usernames:
                print(f"[WARNING] ML detected SQL injection in legitimate username '{username}' - Bypassing detection")
            
            # Check password for SQL injection
            password_prediction, password_prob = ml_detector.sql_injection_detector.predict_sql_injection(password)
            if password_prediction == 1 and not sql_injection_detected:
                sql_detection_data = ml_detector.detect_sql_injection(password, ip_address)
                sql_injection_detected = True
                print(f" SQL Injection detected in password: {password} (Probability: {password_prob:.2f})")
        
        # Store login attempt in database
        login_attempt = LoginAttempt(
            username=username,
            password=password,  # In production, you might want to hash this
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,  # Default to False, will update if successful
            session_id=None
        )
        
        # Add ML detection data if SQL injection was detected
        if sql_detection_data:
            login_attempt.ml_prediction = sql_detection_data['prediction']
            login_attempt.ml_probability = sql_detection_data['probability']
            login_attempt.ml_detected_at = sql_detection_data['detected_at']
        
        db.session.add(login_attempt)
        
        # Check credentials (only if no SQL injection detected)
        success = False
        if not sql_injection_detected:
            success = (username == 'admin' and password == 'admin123')
        
        login_attempt.success = success
        db.session.commit()
        
        # Store SQL injection detection in ML detections table
        if sql_detection_data:
            try:
                # Only store if not a legitimate username bypass
                if username_prediction == 1 and username.lower() in legitimate_usernames:
                    print(f"[WARNING] Skipping ML detection storage for legitimate username: {username}")
                else:
                    ml_detection = MLDetection(
                        login_attempt_id=login_attempt.id,
                        features=json.dumps(sql_detection_data['features']),
                        prediction=sql_detection_data['prediction'],
                        probability=sql_detection_data['probability'],
                        source_ip=sql_detection_data['source_ip'],
                        attack_type='sql_injection',
                        detected_at=sql_detection_data['detected_at']
                    )
                    db.session.add(ml_detection)
                    db.session.commit()
                    print(f" SQL injection detection stored in database")
                
                # Save to JSON file
                save_sql_injection_to_json(sql_detection_data)
                
            except Exception as e:
                print(f" Error storing SQL injection detection: {e}")
                db.session.rollback()
        
        # Log attack attempt (regardless of success)
        attack_log = AttackLog(
            attack_type='sql_injection' if sql_injection_detected else 'brute_force',
            source_ip=ip_address,
            target_url='/login',
            target_host=request.host,
            payload=f'Username: {username}, Password: {password}',
            status_code=403 if sql_injection_detected else (302 if success else 401),
            method='POST',
            user_agent=user_agent,
            severity='high' if sql_injection_detected else ('low' if success else 'medium'),
            description='SQL Injection attack detected and blocked' if sql_injection_detected else (f'Successful login for user: {username}' if success else f'Failed login attempt for user: {username}'),
            raw_data=str(dict(request.form))
        )
        db.session.add(attack_log)
        db.session.commit()
        
        if success:
            session['authenticated'] = True
            session['username'] = username
            login_attempt.session_id = session.get('csrf_token', '')
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        else:
            error_msg = 'Invalid username or password'
            if sql_injection_detected:
                error_msg = 'Attack detected - Login blocked'
            return render_template('login.html', error=error_msg)
    
    return render_template('login.html')

def save_sql_injection_to_json(detection_data):
    """Save SQL injection detection to JSON file"""
    try:
        json_file = 'sql_injection_results.json'
        
        # Load existing data or create new structure
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
        else:
            data = {
                'scan_info': {
                    'target': 'localhost:5000/login',
                    'scan_type': 'sql_injection_detection',
                    'timestamp': datetime.now().isoformat(),
                    'total_attempts': 0
                },
                'results': []
            }
        
        # Add detection result
        result = {
            'request': len(data['results']) + 1,
            'query': detection_data['original_data']['query'],
            'source_ip': detection_data['source_ip'],
            'prediction': detection_data['prediction'],
            'probability': detection_data['probability'],
            'status_code': 403,  # Blocked
            'comment': 'SQL INJECTION ATTACK DETECTED AND BLOCKED',
            'timestamp': detection_data['timestamp'],
            'attack_type': 'sql_injection'
        }
        
        data['results'].append(result)
        data['scan_info']['total_attempts'] = len(data['results'])
        data['scan_info']['timestamp'] = datetime.now().isoformat()
        
        # Save to file
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f" SQL injection detection saved to {json_file}")
        
    except Exception as e:
        print(f" Error saving SQL injection to JSON: {e}")

@app.route('/admin')
def admin_dashboard():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    # Get login statistics
    total_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    success_attempts = LoginAttempt.query.filter_by(success=True).count()
    unique_ips = db.session.query(LoginAttempt.ip_address).distinct().count()
    
    # Get recent attempts
    recent_attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(10).all()
    
    print(f"DEBUG: Admin dashboard stats - Total: {total_attempts}, Failed: {failed_attempts}, Success: {success_attempts}")
    print(f"DEBUG: Recent attempts count: {len(recent_attempts)}")
    
    # Generate security alerts
    security_alerts = []

    if failed_attempts >= 5:
        security_alerts.append(f'High number of failed login attempts: {failed_attempts}')

    if total_attempts >= 3:
        failure_rate = (failed_attempts / total_attempts) * 100
        if failure_rate >= 60:
            security_alerts.append(
                f'Login failure rate is elevated: {failure_rate:.0f}% ({failed_attempts}/{total_attempts})'
            )

    # Check for suspicious activity from same IP
    suspicious_ips = db.session.query(
        LoginAttempt.ip_address,
        db.func.count(LoginAttempt.id).label('count')
    ).filter_by(success=False).group_by(
        LoginAttempt.ip_address
    ).having(db.func.count(LoginAttempt.id) >= 3).all()

    for ip, count in suspicious_ips:
        security_alerts.append(f'Suspicious activity from {ip}: {count} failed attempts')

    # Include recent high-severity attack logs so alerts reflect detected attacks
    recent_high_logs = AttackLog.query.filter(
        db.func.lower(AttackLog.severity).in_(['high', 'critical'])
    ).order_by(AttackLog.timestamp.desc()).limit(3).all()

    for log in recent_high_logs:
        attack_label = (log.attack_type or 'unknown').replace('_', ' ').title()
        source_ip = log.source_ip or 'Unknown IP'
        log_time = format_display_timestamp(log.timestamp)
        security_alerts.append(f'{attack_label} alert from {source_ip} at {log_time}')

    # Keep the panel focused on the most relevant few alerts
    security_alerts = security_alerts[:5]
    
    print(f"DEBUG: Security alerts: {security_alerts}")
    
    return render_template('admin_dashboard.html',
                         total_attempts=total_attempts,
                         failed_attempts=failed_attempts,
                         success_attempts=success_attempts,
                         unique_ips=unique_ips,
                         recent_attempts=recent_attempts,
                         security_alerts=security_alerts,
                         session_username=session.get('username', 'Admin'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/logs', methods=['GET'])
def get_logs():
    attack_type = request.args.get('type')
    limit = request.args.get('limit', 100, type=int)
    
    query = AttackLog.query
    if attack_type:
        query = query.filter_by(attack_type=attack_type)
    
    logs = query.order_by(AttackLog.timestamp.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])

@app.route('/api/logs/burp', methods=['POST'])
def log_burp_attack():
    try:
        data = request.get_json()
        
        # Extract Burp Suite request data
        log_entry = AttackLog(
            attack_type='burp',
            source_ip=request.remote_addr,
            target_url=data.get('url'),
            target_host=data.get('host'),
            payload=data.get('payload'),
            status_code=data.get('status_code'),
            response_size=data.get('response_size'),
            method=data.get('method'),
            user_agent=data.get('user_agent'),
            raw_data=str(data),
            severity=data.get('severity', 'medium'),
            description=f"Burp Suite attack: {data.get('attack_type', 'unknown')}"
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'status': 'success', 'id': log_entry.id}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/logs/sql_injection', methods=['POST'])
def log_sql_injection():
    try:
        data = request.get_json()
        
        log_entry = AttackLog(
            attack_type='sql_injection',
            source_ip=request.remote_addr,
            target_url=data.get('url'),
            target_host=data.get('host'),
            payload=data.get('payload'),
            status_code=data.get('status_code'),
            method=data.get('method'),
            user_agent=data.get('user_agent'),
            raw_data=str(data),
            severity=data.get('severity', 'high'),
            description=f"SQL Injection attempt: {data.get('payload_type', 'unknown')}"
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'status': 'success', 'id': log_entry.id}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/logs/nmap', methods=['POST'])
def log_nmap_scan():
    try:
        data = request.get_json()
        
        log_entry = AttackLog(
            attack_type='nmap',
            source_ip=request.remote_addr,
            target_host=data.get('target'),
            payload=data.get('command'),
            raw_data=str(data),
            severity=data.get('severity', 'medium'),
            description=f"Nmap scan: {data.get('scan_type', 'unknown')} on {data.get('target')}"
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'status': 'success', 'id': log_entry.id}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total_logs = AttackLog.query.count()
    burp_logs = AttackLog.query.filter_by(attack_type='burp').count()
    sql_logs = AttackLog.query.filter_by(attack_type='sql_injection').count()
    nmap_logs = AttackLog.query.filter_by(attack_type='nmap').count()
    
    high_severity = AttackLog.query.filter(AttackLog.severity.in_(['high', 'critical'])).count()
    
    return jsonify({
        'total_logs': total_logs,
        'attack_types': {
            'burp': burp_logs,
            'sql_injection': sql_logs,
            'nmap': nmap_logs,
            'brute_force': AttackLog.query.filter_by(attack_type='brute_force').count()
        },
        'high_severity_alerts': high_severity
    })

@app.route('/api/attack-type-counts', methods=['GET'])
def attack_type_counts():
    counts = db.session.query(AttackLog.attack_type, db.func.count()).group_by(AttackLog.attack_type).all()
    return jsonify({atk: cnt for atk, cnt in counts})

@app.route('/api/logs/brute_force', methods=['POST'])
def log_brute_force():
    """Endpoint for external tools to log brute force attempts"""
    try:
        data = request.get_json()
        
        log_entry = AttackLog(
            attack_type='brute_force',
            source_ip=data.get('source_ip', request.remote_addr),
            target_url=data.get('target_url', '/login'),
            target_host=data.get('target_host', request.host),
            payload=data.get('payload'),
            status_code=data.get('status_code'),
            method=data.get('method', 'POST'),
            user_agent=data.get('user_agent'),
            raw_data=str(data),
            severity=data.get('severity', 'medium'),
            description=data.get('description', 'Brute force attack attempt')
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'status': 'success', 'id': log_entry.id}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/recent-activity', methods=['GET'])
def get_recent_activity():
    """Get recent login activity for real-time updates"""
    try:
        # Get the most recent login attempt
        recent = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(1).first()
        
        if recent:
            # Only return as new activity if it's within the last 2 minutes
            from datetime import datetime, timedelta
            two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)
            
            is_recent = recent.timestamp > two_minutes_ago
            
            return jsonify({
                'new_activity': is_recent,
                'activity': recent.to_dict() if is_recent else None,
                'timestamp': serialize_timestamp(recent.timestamp)
            })
        
        return jsonify({'new_activity': False, 'timestamp': None})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ml-analysis')
def ml_analysis():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    return render_template('ml_analysis.html', session_username=session.get('username', 'Admin'))

@app.route('/api/ml-status')
def ml_status():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    """Get ML model status"""
    return jsonify(ml_detector.get_model_status())

@app.route('/api/ml-analyze-json', methods=['POST'])
def ml_analyze_json():
    """Analyze JSON file for ML detection"""
    try:
        # Analyze the JSON file
        analyzed_data = ml_detector.analyze_json_file('brute_force_results.json')
        
        # Store detection results in database
        detections_stored = 0
        for data in analyzed_data:
            if data['prediction'] is not None and data['prediction'] == 1:  # Attack detected
                # Create ML detection record
                ml_detection = MLDetection(
                    features=json.dumps(data['features']),
                    prediction=data['prediction'],
                    probability=data['probability'],
                    source_ip=data['original_data'].get('source_ip', '127.0.0.1'),
                    attack_type='brute_force'
                )
                db.session.add(ml_detection)
                detections_stored += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'total_analyzed': len(analyzed_data),
            'attacks_detected': len([d for d in analyzed_data if d.get('is_attack', False)]),
            'detections_stored': detections_stored,
            'model_status': ml_detector.get_model_status()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml-detections', methods=['DELETE'])
def clear_ml_detections():
    """Clear all ML detections from database"""
    try:
        # Get all ML detections
        all_detections = MLDetection.query.all()
        deleted_count = len(all_detections)
        
        # Delete all detections
        for detection in all_detections:
            db.session.delete(detection)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully cleared {deleted_count} ML detections',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error clearing ML detections: {str(e)}'
        }), 500

@app.route('/api/ml-detections')
def ml_detections():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    """Get recent ML detections as simple cards"""
    try:
        # Get attack detections from database
        detections = MLDetection.query.filter_by(prediction=1).order_by(MLDetection.detected_at.desc()).limit(20).all()
        
        detection_cards = []
        for detection in detections:
            detection_cards.append({
                'id': detection.id,
                'timestamp': serialize_timestamp(detection.detected_at),
                'source_ip': detection.source_ip,
                'attack_type': detection.attack_type,
                'detected_at': format_display_timestamp(detection.detected_at),
                'severity': get_detection_severity(detection),
                'probability': round(float(detection.probability or 0.0), 4)
            })
        
        return jsonify({
            'success': True,
            'detections': detection_cards,
            'total_count': len(detection_cards)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml-stats')
def ml_stats():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    """Get ML detection statistics"""
    try:
        # Get total attack detections (prediction = 1)
        attack_detections = MLDetection.query.filter_by(prediction=1).count()
        brute_force = MLDetection.query.filter_by(prediction=1, attack_type='brute_force').count()
        sql_injection = MLDetection.query.filter_by(prediction=1, attack_type='sql_injection').count()

        critical = 0
        for detection in MLDetection.query.filter_by(prediction=1).all():
            if get_detection_severity(detection) == 'critical':
                critical += 1
        
        # Get recent detections (last 24 hours)
        from datetime import timedelta
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_detections = MLDetection.query.filter(
            MLDetection.detected_at >= yesterday,
            MLDetection.prediction == 1
        ).count()
        
        return jsonify({
            'success': True,
            'attack_detections': attack_detections,
            'recent_detections': recent_detections,
            'brute_force': brute_force,
            'sql_injection': sql_injection,
            'total': attack_detections,
            'critical': critical,
            'model_status': ml_detector.get_model_status()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def store_ml_detections():
    """Store ML detections in database (called on startup and monitoring)"""
    try:
        if ml_detector.brute_force_detector.is_loaded:
            # Only analyze if file exists
            if os.path.exists('brute_force_results.json'):
                # Get detections from ML service
                attack_detections = ml_detector.analyze_brute_force_detections('brute_force_results.json')
            else:
                print("DEBUG: brute_force_results.json not found, skipping brute force analysis")
                attack_detections = []
            
            # Store in database
            for detection in attack_detections:
                # Check if already stored to avoid duplicates
                existing = MLDetection.query.filter_by(
                    source_ip=detection['source_ip'],
                    detected_at=detection['detected_at']
                ).first()
                
                if not existing:
                    ml_detection = MLDetection(
                        features=json.dumps(detection['features']),
                        prediction=detection['prediction'],
                        probability=detection['probability'],
                        source_ip=detection['source_ip'],
                        attack_type='brute_force',
                        detected_at=detection['detected_at']
                    )
                    db.session.add(ml_detection)
            
            db.session.commit()
            if attack_detections:
                print(f"[SUCCESS] Stored {len(attack_detections)} new ML detections in database")
            
    except Exception as e:
        print(f"[ERROR] Error storing ML detections: {e}")
        db.session.rollback()

def continuous_ml_store():
    """Background function to continuously store ML detections"""
    while ml_detector.monitoring_active:
        try:
            store_ml_detections()
            time.sleep(15)  # Check every 15 seconds for new detections
        except Exception as e:
            print(f"[ERROR] Error in continuous ML storage: {e}")
            time.sleep(30)

@app.route('/clear-logs')
def clear_logs_page():
    # Check if user should be blocked due to recent attacks
    block_response = check_attack_blocking()
    if block_response:
        return block_response
    
    """Serve the clear logs page"""
    return render_template('clear_logs.html', session_username=session.get('username', 'Admin'))

@app.route('/api/clear-logs/<log_type>', methods=['DELETE'])
def clear_logs_api(log_type):
    """API endpoint to clear specific types of logs"""
    try:
        import os
        import glob
        
        deleted_count = 0
        json_cleared = False
        
        if log_type == 'brute-force':
            # Get brute force logs first (before deleting)
            brute_force_logs = AttackLog.query.filter_by(attack_type='brute_force').all()
            
            # Get IPs from brute force logs
            brute_force_ips = set()
            for log in brute_force_logs:
                if log.source_ip:
                    brute_force_ips.add(log.source_ip)
            
            # Clear brute force logs from database
            for log in brute_force_logs:
                db.session.delete(log)
            deleted_count += len(brute_force_logs)
            
            # Clear ALL login attempts (safer approach for brute force)
            # Since most login attempts come from brute force testing
            all_login_attempts = LoginAttempt.query.all()
            for attempt in all_login_attempts:
                db.session.delete(attempt)
            deleted_count += len(all_login_attempts)
            
            # Clear brute force JSON files
            json_files = ['brute_force_results.json']
            for json_file in json_files:
                if os.path.exists(json_file):
                    os.remove(json_file)
                    json_cleared = True
            
        elif log_type == 'burp-suite':
            # Get Burp Suite logs first
            # Bug 4 fix: attack_type is stored as 'burp' not 'burp_suite'
            burp_logs = AttackLog.query.filter(AttackLog.attack_type.in_(['burp', 'sql_injection', 'nmap'])).all()
            
            # Get IPs from Burp Suite logs
            burp_ips = set()
            for log in burp_logs:
                if log.source_ip:
                    burp_ips.add(log.source_ip)
            
            # Clear Burp Suite logs from database
            for log in burp_logs:
                db.session.delete(log)
            deleted_count += len(burp_logs)
            
            # Clear login attempts from Burp Suite IPs
            if burp_ips:
                for ip in burp_ips:
                    login_attempts = LoginAttempt.query.filter_by(ip_address=ip).all()
                    for attempt in login_attempts:
                        db.session.delete(attempt)
                        deleted_count += 1
            
            # Clear Burp Suite related JSON files
            json_files = ['burp_suite_results.json', 'sql_injection_results.json', 'nmap_results.json']
            for json_file in json_files:
                if os.path.exists(json_file):
                    os.remove(json_file)
                    json_cleared = True
            
        elif log_type == 'all':
            # Clear all attack logs from database
            all_logs = AttackLog.query.all()
            for log in all_logs:
                db.session.delete(log)
            deleted_count += len(all_logs)
            
            # Clear ALL login attempts
            login_attempts = LoginAttempt.query.all()
            for attempt in login_attempts:
                db.session.delete(attempt)
            deleted_count += len(login_attempts)
            
            # Clear ALL ML detections
            ml_detections = MLDetection.query.all()
            for detection in ml_detections:
                db.session.delete(detection)
            deleted_count += len(ml_detections)
            
            # Clear all JSON result files
            json_files = glob.glob('*.json')
            for json_file in json_files:
                if os.path.exists(json_file):
                    os.remove(json_file)
                    json_cleared = True
            
        else:
            return jsonify({'message': 'Invalid log type'}), 400
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully cleared {deleted_count} logs',
            'deleted_count': deleted_count,
            'log_type': log_type,
            'json_cleared': json_cleared,
            'attack_logs_cleared': deleted_count,
            'login_attempts_cleared': 'all' if log_type == 'all' else 'related'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error clearing logs: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Ensure database is properly initialized
        db.create_all()
        
        # Check if database file exists and has content
        db_path = 'cybersec_logs.db'
        if os.path.exists(db_path):
            size = os.path.getsize(db_path)
            if size == 0:
                print("Warning: Database file is empty, reinitializing...")
                db.drop_all()
                db.create_all()
                print("Database reinitialized successfully!")
            else:
                print(f"Database ready: {size} bytes")
                
                # Check if new columns exist, if not, add them
                try:
                    # Try to access new ML fields to see if they exist
                    from sqlalchemy import text
                    connection = db.engine.connect()
                    
                    # Check if ml_prediction column exists in login_attempt table
                    result = connection.execute(text("PRAGMA table_info(login_attempt)"))
                    columns = [row[1] for row in result]
                    
                    if 'ml_prediction' not in columns:
                        print("Adding ML fields to login_attempt table...")
                        connection.execute(text("ALTER TABLE login_attempt ADD COLUMN ml_prediction INTEGER"))
                        connection.execute(text("ALTER TABLE login_attempt ADD COLUMN ml_probability FLOAT"))
                        connection.execute(text("ALTER TABLE login_attempt ADD COLUMN ml_detected_at DATETIME"))
                        connection.commit()
                        print("ML fields added successfully!")
                    
                    connection.close()
                    
                except Exception as e:
                    print(f"Note: Could not update database schema: {e}")
        else:
            print("Creating new database...")
            db.create_all()
            
        # Store ML detections automatically on startup
        print("[ML] Initializing ML detection system...")
        store_ml_detections()
        
        # Start continuous ML storage thread
        ml_storage_thread = threading.Thread(target=continuous_ml_store, daemon=True)
        ml_storage_thread.start()
        print("[THREAD] Started continuous ML storage thread")
            
    print(f"ML Model Status: {ml_detector.get_model_status()}")
    app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
