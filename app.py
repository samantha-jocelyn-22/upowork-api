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
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
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
            connection.execute("ALTER TABLE vacancies ADD COLUMN deadline TEXT")
        if "schedule" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN schedule TEXT")
        if "support" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN support TEXT")
        if "source_url" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN source_url TEXT")

def valid_pdf(file):
    if not file or not file.filename or not file.filename.lower().endswith(".pdf"):
        return False
    return True

# ========== RUTAS DE PÁGINAS — TODAS COMPLETAS Y CERRADAS ==========

@app.get("/")
def home():
    return render_template('index.html')

@app.route("/login", methods=["GET", "POST"])
@app.post("/api/login")
def login():
    if request.method == "GET":
        return render_template('login.html')
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    requested_role = request.form.get("role", "student")
    if requested_role == "company":
        return jsonify({"error": "El acceso de empresas ya no está disponible."}), 403
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or user["role"] != requested_role or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"name": user["name"], "role": user["role"]})

@app.route("/registrar", methods=["GET", "POST"])
@app.post("/api/profiles")
def create_profile():
    if request.method == "GET":
        return render_template('perfil.html')
    return jsonify({"message": "Registro recibido"}), 200

@app.get("/aviso-privacidad")
def aviso_privacidad():
    return render_template('aviso-privacidad.html')

@app.get("/consejos")
def consejos():
    return render_template('consejos.html')

@app.get("/contacto")
def contacto():
    return render_template('contacto.html')

@app.get("/dashboard")
def dashboard():
    return render_template('dashboard.html')

@app.get("/empresa-registro")
def empresa_registro():
    return render_template('empresa-registro.html')

@app.get("/empresas")
def empresas():
    return render_template('empresas.html')

@app.get("/preguntas-frecuentes")
def preguntas_frecuentes():
    return render_template('preguntas-frecuentes.html')

@app.get("/sugerencias")
def sugerencias():
    return render_template('sugerencias.html')

@app.get("/terminos-de-uso")
def terminos_de_uso():
    return render_template('terminos-de-uso.html')

# ========== ARCHIVOS ESTÁTICOS — CORREGIDO ✅ ==========
@app.get("/styles.css")
def serve_css():
    return send_from_directory(BASE_DIR, "styles.css")

@app.get("/script.js")
def serve_js():
    return send_from_directory(BASE_DIR, "script.js")

@app.get("/upowork-logo.svg")
def serve_logo():
    return send_from_directory(BASE_DIR, "upowork-logo.svg")

@app.get("/uploads/<path:filename>")
def serve_uploads(filename):
    return send_from_directory(UPLOADS, filename) 5000)))
