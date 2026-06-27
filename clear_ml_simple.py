#!/usr/bin/env python3
"""
Simple script to clear ML detection records
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, MLDetection
    
    with app.app_context():
        # Count and delete all ML detections
        count = MLDetection.query.count()
        print(f'Found {count} ML detection records')
        
        if count > 0:
            MLDetection.query.delete()
            db.session.commit()
            print(f'Deleted {count} ML detection records')
        
        print('Database cleared successfully')
        
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
