from pathlib import Path
import sqlite3
import os
import re
import uuid
import csv
import secrets
from io import StringIO
from functools import wraps
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from flask import Flask, jsonify, request, send_from_directory, session, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path("./upotec.db")
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "static" / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app_environment = os.environ.get("UPOWORK_ENV", "development").lower()
secret_key = os.environ.get("UPOWORK_SECRET_KEY")
if app_environment == "production" and not secret_key:
    raise RuntimeError("UPOWORK_SECRET_KEY debe configurarse en producción.")
app.secret_key = secret_key or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=app_environment == "production" or os.environ.get("UPOWORK_HTTPS", "").lower() == "true",
)

ALLOWED_EXTENSIONS = {"pdf"}

@app.before_request
def validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(expected, provided):
        return jsonify({"error": "La sesión expiró o la solicitud no es válida. Recarga la página e inténtalo de nuevo."}), 400
    return None

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def initialize_database():
    with get_db() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                career TEXT NOT NULL,
                interest TEXT NOT NULL,
                skills TEXT NOT NULL,
                cv_filename TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                privacy_consent INTEGER NOT NULL DEFAULT 0,
                approval_status TEXT NOT NULL DEFAULT 'pending',
                approval_note TEXT
            );
            CREATE TABLE IF NOT EXISTS suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                category TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','reviewing','resolved')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                area TEXT NOT NULL,
                mode TEXT NOT NULL,
                distance TEXT NOT NULL,
                vacancies INTEGER NOT NULL DEFAULT 0,
                is_demo INTEGER NOT NULL DEFAULT 0,
                approval_status TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS vacancies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'presencial',
                location TEXT,
                requirements TEXT,
                career TEXT,
                opportunity_type TEXT NOT NULL DEFAULT 'empleo',
                deadline TEXT,
                schedule TEXT,
                support TEXT,
                source_url TEXT,
                status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vacancy_id INTEGER NOT NULL REFERENCES vacancies(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','reviewing','accepted','rejected','withdrawn')),
                cover_note TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(vacancy_id, student_id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                read_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'company'))
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
                worked TEXT NOT NULL CHECK (worked IN ('yes', 'partially', 'no')),
                comment TEXT NOT NULL,
                show_name INTEGER NOT NULL DEFAULT 0 CHECK (show_name IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        student_columns = {row["name"] for row in connection.execute("PRAGMA table_info(students)")}
        if "privacy_consent" not in student_columns:
            connection.execute("ALTER TABLE students ADD COLUMN privacy_consent INTEGER NOT NULL DEFAULT 0")
        if "approval_status" not in student_columns:
            connection.execute("ALTER TABLE students ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        if "approval_note" not in student_columns:
            connection.execute("ALTER TABLE students ADD COLUMN approval_note TEXT")
        company_columns = {row["name"] for row in connection.execute("PRAGMA table_info(companies)")}
        if "is_demo" not in company_columns:
            connection.execute("ALTER TABLE companies ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0")
        if "approval_status" not in company_columns:
            connection.execute("ALTER TABLE companies ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        vacancy_columns = {row["name"] for row in connection.execute("PRAGMA table_info(vacancies)")}
        if "career" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN career TEXT")
        if "opportunity_type" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN opportunity_type TEXT NOT NULL DEFAULT 'empleo'")
        if "deadline" not in vacancy_columns:
            connection.execute("ALTER
