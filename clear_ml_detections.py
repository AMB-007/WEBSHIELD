#!/usr/bin/env python3
"""
Script to clear old ML detection records (older than 1 hour)
"""

import os
import sys
from datetime import datetime, timedelta

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, MLDetection
    
    with app.app_context():
        # Delete only old ML detections (older than 1 hour) to clean up
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        old_detections = MLDetection.query.filter(
            MLDetection.detected_at < one_hour_ago
        ).all()
        count = len(old_detections)
        
        print(f'Found {count} old ML detection records (older than 1 hour):')
        for detection in old_detections:
            print(f'  - {detection.detected_at} | {detection.attack_type} | {detection.source_ip}')
        
        # Delete only old detections
        for detection in old_detections:
            db.session.delete(detection)
        
        db.session.commit()
        print(f'Successfully deleted {count} old ML detection records')
        
        # Show recent detections that are kept
        recent_detections = MLDetection.query.filter(
            MLDetection.detected_at >= one_hour_ago
        ).all()
        print(f'Kept {len(recent_detections)} recent ML detection records for dashboard display')
        
except Exception as e:
    print(f'Error: {e}')
    print('Make sure you have installed all required packages')
