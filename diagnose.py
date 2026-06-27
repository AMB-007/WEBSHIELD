import traceback, sys

# Test imports one by one
try:
    print("Testing Flask...", flush=True)
    from flask import Flask, request, jsonify, render_template, session, redirect, url_for
    print("Flask OK", flush=True)
except Exception as e:
    print(f"Flask FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    print("Testing flask_sqlalchemy...", flush=True)
    from flask_sqlalchemy import SQLAlchemy
    print("SQLAlchemy OK", flush=True)
except Exception as e:
    print(f"SQLAlchemy FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    print("Testing flask_cors...", flush=True)
    from flask_cors import CORS
    print("CORS OK", flush=True)
except Exception as e:
    print(f"CORS FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    print("Testing dotenv...", flush=True)
    from dotenv import load_dotenv
    load_dotenv()
    print("dotenv OK", flush=True)
except Exception as e:
    print(f"dotenv FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    print("Testing ml_service...", flush=True)
    from ml_service import ml_detector
    print("ml_service OK", flush=True)
except Exception as e:
    print(f"ml_service FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    print("Testing zoneinfo...", flush=True)
    from zoneinfo import ZoneInfo
    ZoneInfo("Asia/Kolkata")
    print("zoneinfo OK", flush=True)
except Exception as e:
    print(f"zoneinfo FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

print("All imports OK!", flush=True)
