#!/usr/bin/env python3
"""
Script to generate test SQL injection ML detections for dashboard testing
"""

import os
import sys
from datetime import datetime, timedelta

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, MLDetection
    
    with app.app_context():
        # Create some test SQL injection detections
        test_detections = [
            {
                'features': '{"query": "admin OR 1=1--", "source_ip": "127.0.0.1"}',
                'prediction': 1,
                'probability': 0.95,
                'source_ip': '127.0.0.1',
                'attack_type': 'sql_injection',
                'detected_at': datetime.utcnow() - timedelta(minutes=5)
            },
            {
                'features': '{"query": "admin; DROP TABLE users--", "source_ip": "127.0.0.1"}',
                'prediction': 1,
                'probability': 0.98,
                'source_ip': '127.0.0.1',
                'attack_type': 'sql_injection',
                'detected_at': datetime.utcnow() - timedelta(minutes=3)
            },
            {
                'features': '{"query": "UNION SELECT * FROM passwords--", "source_ip": "192.168.1.100"}',
                'prediction': 1,
                'probability': 0.92,
                'source_ip': '192.168.1.100',
                'attack_type': 'sql_injection',
                'detected_at': datetime.utcnow() - timedelta(minutes=2)
            }
        ]
        
        print(f'Creating {len(test_detections)} test SQL injection detections...')
        
        for detection_data in test_detections:
            ml_detection = MLDetection(
                features=detection_data['features'],
                prediction=detection_data['prediction'],
                probability=detection_data['probability'],
                source_ip=detection_data['source_ip'],
                attack_type=detection_data['attack_type'],
                detected_at=detection_data['detected_at']
            )
            db.session.add(ml_detection)
        
        db.session.commit()
        print(f'Successfully created {len(test_detections)} test SQL injection detections')
        print('You can now see these in the ML Analysis dashboard!')
        
except Exception as e:
    print(f'Error: {e}')
    print('Make sure you have installed all required packages')
