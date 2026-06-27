#!/usr/bin/env python3
"""
Script to clear all old ML detection records to fix blocking issue
"""

import os
import sys
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, MLDetection
    
    with app.app_context():
        # Get all ML detections
        all_detections = MLDetection.query.all()
        count = len(all_detections)
        
        print(f'Found {count} ML detection records:')
        for detection in all_detections:
            print(f'  - {detection.detected_at} | {detection.attack_type} | {detection.source_ip}')
        
        # Delete all ML detections
        for detection in all_detections:
            db.session.delete(detection)
        
        db.session.commit()
        print(f'Successfully deleted {count} ML detection records')
        print('Database is now clean - no more blocking!')
        
except Exception as e:
    print(f'Error: {e}')
    print('Make sure you have installed all required packages')
