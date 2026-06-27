#!/usr/bin/env python3
"""
ML Service for Brute Force and SQL Injection Attack Detection
"""

import json
import hashlib
import threading
import time
import os
import re
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional

# Gracefully handle ML dependencies to run in rule-based fallback mode if they are blocked by AppLocker/Application Control policy
try:
    import joblib
    import pandas as pd
    import numpy as np
    ML_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] ML dependencies failed to import: {e}")
    print("[WARNING] Running in Rule-Based Fallback Threat Detection mode!")
    ML_AVAILABLE = False

class BruteForceMLDetector:
    """ML-based brute force attack detector"""
    
    def __init__(self, model_path='arjun/bruteforce_rf_model.pkl'):  # Bug 2 fix: was 'deepu/' which doesn't exist
        self.model = None
        self.is_loaded = False
        self.model_path = model_path
        self.last_detection_time = None
        self.monitoring_active = False
        self.monitoring_thread = None
        self.last_file_modified = None
        self.is_fallback = False
        self.load_model()
    
    def load_model(self):
        """Load the ML model on initialization"""
        if not ML_AVAILABLE:
            print("[INFO] ML dependencies unavailable. Brute Force Detector running in Rule-Based Fallback mode.")
            self.is_loaded = True
            self.is_fallback = True
            return
        try:
            self.model = joblib.load(self.model_path)
            print(f"[SUCCESS] Brute Force ML Model loaded successfully from {self.model_path}")
            self.is_loaded = True
            self.is_fallback = False
        except FileNotFoundError:
            print(f"[ERROR] Brute Force ML Model not found at {self.model_path}. Using fallback.")
            self.is_loaded = True
            self.is_fallback = True
        except Exception as e:
            print(f"[ERROR] Failed to load Brute Force ML model: {e}. Using fallback.")
            self.is_loaded = True
            self.is_fallback = True
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring in background thread"""
        if self.is_loaded and not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self.continuous_monitor, daemon=True)
            self.monitoring_thread.start()
            print("[MONITOR] Started continuous ML monitoring...")
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("[STOP] Stopped continuous ML monitoring")
    
    def continuous_monitor(self):
        """Background thread for continuous monitoring"""
        while self.monitoring_active:
            try:
                self.check_and_detect()
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                print(f"[ERROR] Error in continuous monitoring: {e}")
                time.sleep(30)  # Wait longer on error
    
    def get_file_modified_time(self, file_path='brute_force_results.json'):
        """Get the last modified time of the JSON file"""
        try:
            import os
            return os.path.getmtime(file_path)
        except:
            return None
    
    def check_and_detect(self):
        """Check for new data and run detection if needed"""
        try:
            current_modified = self.get_file_modified_time('brute_force_results.json')
            
            # If file is new or modified, run detection
            if (self.last_file_modified is None or 
                current_modified is None or 
                current_modified > self.last_file_modified):
                
                print(f"[MONITOR] New data detected, running ML analysis...")
                new_detections = self.analyze_and_store_detections()
                
                if new_detections:
                    print(f"[ALERT] Detected {len(new_detections)} new attacks!")
                    # Here you could trigger alerts or notifications
                
                self.last_file_modified = current_modified
                
        except Exception as e:
            print(f"[ERROR] Error checking for new data: {e}")
    
    def encode_ip(self, ip_str: str) -> int:
        """Convert IP string to numerical value"""
        try:
            # Simple hash-based encoding for IP addresses
            return int(hashlib.md5(ip_str.encode()).hexdigest()[:8], 16) % 10000
        except:
            return 0
    
    def extract_password_length(self, payload: str) -> int:
        """Extract password length from payload string"""
        try:
            # Extract password from payload like "Username: admin, Password: admin123"
            if "Password:" in payload:
                password_part = payload.split("Password:")[1].strip()
                password = password_part.split(",")[0] if "," in password_part else password_part
                return len(password)
            return 0
        except:
            return 0
    
    def count_attempts_per_ip(self, ip: str, all_attempts: list) -> int:
        """Count total attempts from this IP"""
        try:
            return sum(1 for attempt in all_attempts if attempt.get('source_ip') == ip)
        except:
            return 1
    
    def extract_features_from_json(self, json_data: Dict, all_attempts: list = None) -> Dict:
        """Extract features from JSON attack data"""
        try:
            # Extract payload for password length
            payload = json_data.get('payload', '')
            if not payload:
                # Combine payload1 and payload2 if available
                payload1 = json_data.get('payload1', '')
                payload2 = json_data.get('payload2', '')
                payload = f"Username: {payload1}, Password: {payload2}"
            
            features = {
                'ip': self.encode_ip(json_data.get('source_ip', '127.0.0.1')),
                'password_length': self.extract_password_length(payload),
                'status': json_data.get('status_code', 200),
                'response_size': json_data.get('length', 0),
                'time_diff': json_data.get('response_time', 0.0),
                'attempt_count_ip': self.count_attempts_per_ip(
                    json_data.get('source_ip', '127.0.0.1'), 
                    all_attempts or []
                ),
                'failed_flag': 1 if 'FAILED' in json_data.get('comment', '').upper() else 0
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            # Return default features
            return {
                'ip': 0,
                'password_length': 0,
                'status': 200,
                'response_size': 0,
                'time_diff': 0.0,
                'attempt_count_ip': 1,
                'failed_flag': 0
            }
    
    def predict_attack(self, features: Dict) -> Tuple[Optional[int], float]:
        """Predict if the attack is malicious"""
        if self.is_fallback or self.model is None:
            attempt_count = features.get('attempt_count_ip', 0)
            failed_flag = features.get('failed_flag', 0)
            if attempt_count > 5:
                prob = 0.80 + min(0.19, (attempt_count - 5) * 0.02)
                return 1, prob
            elif failed_flag == 1 and attempt_count > 3:
                return 1, 0.75
            return 0, 0.05
            
        try:
            # Convert to DataFrame with correct feature order
            feature_order = ['ip', 'password_length', 'status', 'response_size', 
                           'time_diff', 'attempt_count_ip', 'failed_flag']
            
            # Ensure all features exist
            for feature in feature_order:
                if feature not in features:
                    features[feature] = 0
            
            # Create DataFrame
            df = pd.DataFrame([features], columns=feature_order)
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            probability = self.model.predict_proba(df)[0][1]  # Probability of class 1 (attack)
            
            return int(prediction), float(probability)
            
        except Exception as e:
            print(f"Error making prediction: {e}")
            return None, 0.0
    
    def analyze_and_store_detections(self, json_file_path='brute_force_results.json'):
        """Analyze JSON file and store only attack detections"""
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            results = data.get('results', [])
            all_attempts = results  # For counting attempts per IP
            
            attack_detections = []
            
            for attempt in results:
                features = self.extract_features_from_json(attempt, all_attempts)
                prediction, probability = self.predict_attack(features)
                
                # Only store if attack is detected (prediction == 1)
                if prediction == 1:
                    attack_detections.append({
                        'original_data': attempt,
                        'features': features,
                        'prediction': prediction,
                        'probability': probability,
                        'timestamp': datetime.utcnow().isoformat(),  # Bug 3 fix: use utcnow()
                        'is_attack': True,
                        'source_ip': attempt.get('source_ip', '127.0.0.1'),
                        'detected_at': datetime.utcnow(),  # Bug 3 fix: was datetime.now() causing 5.5hr lockout
                        'attack_type': 'brute_force'
                    })
            
            # Store detections in database (will be called from Flask app)
            self.last_detection_time = datetime.now()
            return attack_detections
            
        except Exception as e:
            print(f"Error analyzing JSON file: {e}")
            return []
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'is_monitoring': self.monitoring_active,
            'last_check': datetime.now().isoformat(),
            'last_detection': self.last_detection_time.isoformat() if self.last_detection_time else None,
            'check_interval': '10 seconds'
        }
    
    def get_model_status(self) -> Dict:
        """Get current model status"""
        return {
            'is_loaded': self.is_loaded,
            'loaded': self.is_loaded,
            'is_fallback': self.is_fallback,
            'model_path': self.model_path,
            'status': 'RULE_BASED_FALLBACK' if self.is_fallback else ('ACTIVE' if self.is_loaded else 'INACTIVE'),
            'timestamp': datetime.now().isoformat(),
            'last_detection': self.last_detection_time.isoformat() if self.last_detection_time else None,
            'monitoring_status': self.get_monitoring_status()
        }

class SQLInjectionMLDetector:
    """ML-based SQL injection attack detector"""
    
    def __init__(self, model_path='arjun/rf_sql_model.pkl', vectorizer_path='arjun/tfidf_vectorizer.pkl'):  # Bug 2 fix: was 'deepu/' which doesn't exist
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.is_fallback = False
        self.load_model()
    
    def load_model(self):
        """Load the SQL injection ML model and vectorizer"""
        if not ML_AVAILABLE:
            print("[INFO] ML dependencies unavailable. SQL Injection Detector running in Rule-Based Fallback mode.")
            self.is_loaded = True
            self.is_fallback = True
            return
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.is_loaded = True
            self.is_fallback = False
            print(f"[SUCCESS] SQL Injection ML Model loaded successfully from {self.model_path}")
            print(f"[SUCCESS] TF-IDF Vectorizer loaded successfully from {self.vectorizer_path}")
        except FileNotFoundError as e:
            self.is_loaded = True
            self.is_fallback = True
            if 'rf_sql_model.pkl' in str(e):
                print(f"[ERROR] SQL Injection ML Model not found at {self.model_path}. Using fallback.")
            else:
                print(f"[ERROR] TF-IDF Vectorizer not found at {self.vectorizer_path}. Using fallback.")
        except Exception as e:
            self.is_loaded = True
            self.is_fallback = True
            print(f"[ERROR] Failed to load SQL Injection ML model: {e}. Using fallback.")
    
    def predict_sql_injection(self, query: str) -> Tuple[Optional[int], float]:
        """Predict if the query is SQL injection"""
        if self.is_fallback or self.model is None or self.vectorizer is None:
            if not query:
                return 0, 0.0
            
            query_lower = query.lower()
            sql_patterns = [
                r"union\s+select",
                r"select\s+.*\s+from",
                r"insert\s+into",
                r"delete\s+from",
                r"drop\s+table",
                r"alter\s+table",
                r"'\s*or\s*",
                r"\"\s*or\s*",
                r"'\s*and\s*",
                r"\"\s*and\s*",
                r"--",
                r"/\*",
                r"\*/",
                r"xp_cmdshell",
                r"exec\s*\(",
                r"benchmark\s*\(",
                r"sleep\s*\("
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, query_lower):
                    return 1, 0.92
            
            return 0, 0.02
        
        try:
            # Vectorize the query
            query_vector = self.vectorizer.transform([query])
            
            # Make prediction
            prediction = self.model.predict(query_vector)[0]
            probability = self.model.predict_proba(query_vector)[0][1]  # Probability of class 1 (SQL injection)
            
            return int(prediction), float(probability)
            
        except Exception as e:
            print(f"Error making SQL injection prediction: {e}")
            return None, 0.0
    
    def get_model_status(self) -> Dict:
        """Get current model status"""
        return {
            'is_loaded': self.is_loaded,
            'loaded': self.is_loaded,
            'is_fallback': self.is_fallback,
            'model_path': self.model_path,
            'vectorizer_path': self.vectorizer_path,
            'status': 'RULE_BASED_FALLBACK' if self.is_fallback else ('ACTIVE' if self.is_loaded else 'INACTIVE'),
            'timestamp': datetime.now().isoformat()
        }

class UnifiedMLDetector:
    """Unified ML detector for both brute force and SQL injection attacks"""
    
    def __init__(self):
        self.brute_force_detector = BruteForceMLDetector()
        self.sql_injection_detector = SQLInjectionMLDetector()
        self.monitoring_active = False
        self.monitoring_thread = None
        self.last_file_modified = None
        self.last_sql_check = None
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring in background thread"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self.continuous_monitor, daemon=True)
            self.monitoring_thread.start()
            print("[MONITOR] Started continuous unified ML monitoring...")
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("[STOP] Stopped continuous unified ML monitoring")
    
    def continuous_monitor(self):
        """Background thread for continuous monitoring"""
        while self.monitoring_active:
            try:
                self.check_and_detect()
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                print(f"[ERROR] Error in continuous monitoring: {e}")
                time.sleep(30)  # Wait longer on error
    
    def get_file_modified_time(self, file_path='brute_force_results.json'):
        """Get the last modified time of the JSON file"""
        try:
            return os.path.getmtime(file_path)
        except:
            return None
    
    def check_and_detect(self):
        """Check for new data and run detection if needed"""
        try:
            # Check brute force results
            current_modified = self.get_file_modified_time('brute_force_results.json')
            
            if (self.last_file_modified is None or 
                current_modified is None or 
                current_modified > self.last_file_modified):
                
                print(f"[MONITOR] New brute force data detected, running ML analysis...")
                new_detections = self.analyze_brute_force_detections()
                
                if new_detections:
                    print(f"[ALERT] Detected {len(new_detections)} new brute force attacks!")
                
                self.last_file_modified = current_modified
            
            # Check for new SQL injection attempts (from login attempts)
            self.check_sql_injection_attempts()
                
        except Exception as e:
            print(f"[ERROR] Error checking for new data: {e}")
    
    def check_sql_injection_attempts(self):
        """Check for SQL injection attempts in recent login attempts"""
        try:
            # This will be called from Flask app when login attempts are made
            pass
        except Exception as e:
            print(f"[ERROR] Error checking SQL injection attempts: {e}")
    
    def analyze_brute_force_detections(self, json_file_path='brute_force_results.json'):
        """Analyze JSON file for brute force detections"""
        return self.brute_force_detector.analyze_and_store_detections(json_file_path)
    
    def detect_sql_injection(self, query: str, source_ip: str = '127.0.0.1'):
        """Detect SQL injection in a query"""
        prediction, probability = self.sql_injection_detector.predict_sql_injection(query)
        
        if prediction == 1:  # SQL injection detected
            return {
                'original_data': {'query': query, 'source_ip': source_ip},
                'features': {'query': query},
                'prediction': prediction,
                'probability': probability,
                'timestamp': datetime.utcnow().isoformat(),  # Bug 3 fix: use utcnow()
                'is_attack': True,
                'source_ip': source_ip,
                'detected_at': datetime.utcnow(),  # Bug 3 fix: was datetime.now() causing 5.5hr lockout
                'attack_type': 'sql_injection'
            }
        
        return None
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'is_monitoring': self.monitoring_active,
            'last_check': datetime.now().isoformat(),
            'check_interval': '10 seconds'
        }
    
    def analyze_json_file(self, json_file_path='brute_force_results.json'):
        """Analyze JSON file for ML detection"""
        return self.analyze_brute_force_detections(json_file_path)

    def get_model_status(self) -> Dict:
        """Get current model status"""
        return {
            'brute_force': self.brute_force_detector.get_model_status(),
            'sql_injection': self.sql_injection_detector.get_model_status(),
            'monitoring_status': self.get_monitoring_status(),
            'timestamp': datetime.now().isoformat(),
            'mode': 'Fallback (Rule-Based)' if (self.brute_force_detector.is_fallback or self.sql_injection_detector.is_fallback) else 'ML (Random Forest)'
        }

# Global unified ML detector instance
ml_detector = UnifiedMLDetector()
