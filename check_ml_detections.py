#!/usr/bin/env python3
"""
Script to check current ML detections in database
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
        
        print(f'[INFO] Total ML Detections: {count}')
        
        if count > 0:
            print('\n[INFO] Recent ML Detections:')
            for detection in all_detections[-10:]:  # Show last 10
                print(f'  - {detection.detected_at} | {detection.attack_type} | {detection.source_ip} | Prob: {detection.probability:.2f}')
        else:
            print('[INFO] No ML detections found in database')
        
        # Check for brute force detections specifically
        brute_detections = MLDetection.query.filter_by(attack_type='brute_force').all()
        brute_count = len(brute_detections)
        
        print(f'\n[INFO] Brute Force Detections: {brute_count}')
        if brute_count > 0:
            for detection in brute_detections[-5:]:  # Show last 5
                print(f'  - {detection.detected_at} | {detection.source_ip} | Prob: {detection.probability:.2f}')
        
        # Check for SQL injection detections
        sql_detections = MLDetection.query.filter_by(attack_type='sql_injection').all()
        sql_count = len(sql_detections)
        
        print(f'\n[INFO] SQL Injection Detections: {sql_count}')
        if sql_count > 0:
            for detection in sql_detections[-5:]:  # Show last 5
                print(f'  - {detection.detected_at} | {detection.source_ip} | Prob: {detection.probability:.2f}')
        
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
