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
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

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
        connection.executescript(
            """
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
            """
        )
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
    signature = file.stream.read(5)
    file.stream.seek(0)
    return signature == b"%PDF-"


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/registrar")
def registrar():
    return render_template("perfil.html")


@app.get("/empresas")
def empresas():
    return render_template("empresas.html")


@app.get("/consejos")
def consejos():
    return render_template("consejos.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/aviso-privacidad")
def aviso_privacidad():
    return render_template("aviso-privacidad.html")


@app.get("/contacto")
def contacto():
    return render_template("contacto.html")


@app.get("/terminos-de-uso")
def terminos_de_uso():
    return render_template("terminos-de-uso.html")


@app.get("/preguntas-frecuentes")
def preguntas_frecuentes():
    return render_template("preguntas-frecuentes.html")


@app.get("/sugerencias")
def sugerencias():
    return render_template("sugerencias.html")


@app.get("/opiniones")
def opiniones():
    return render_template("opiniones.html")


def send_frontend_file(filename):
    for directory in (BASE_DIR, BASE_DIR / "templates", BASE_DIR / "static"):
        if (directory / filename).is_file():
            return send_from_directory(directory, filename)
    return jsonify({"error": "No se encontró el archivo solicitado."}), 404


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Inicia sesión para continuar."}), 401
        return view(*args, **kwargs)
    return wrapped


@app.post("/api/login")
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    requested_role = request.form.get("role", "student")
    if requested_role == "company":
        return jsonify({"error": "El acceso de empresas ya no está disponible."}), 403
    with get_db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or user["role"] != requested_role or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401
    csrf = secrets.token_urlsafe(32)
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = csrf
    return jsonify({"name": user["name"], "role": user["role"]})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada."})


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.get("/api/me")
@login_required
def current_user():
    with get_db() as connection:
        user = connection.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    return jsonify(dict(user))


@app.post("/api/profiles")
def create_profile():
    required = ("name", "email", "career", "interest", "skills", "password")
    if any(not request.form.get(field, "").strip() for field in required):
        return jsonify({"error": "Completa todos los campos obligatorios."}), 400
    email = request.form["email"].strip().lower()
    consent = request.form.get("privacy_consent", "").lower() in {"1", "true", "on", "yes"}
    if not consent:
        return jsonify({"error": "Debes aceptar el aviso de privacidad para crear tu perfil."}), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Ingresa un correo válido."}), 400
    cv = request.files.get("cv")
    cv_filename = None
    if cv and cv.filename:
        if not valid_pdf(cv):
            return jsonify({"error": "El CV debe estar en formato PDF."}), 400
        cv_filename = f"{uuid.uuid4().hex}_{secure_filename(cv.filename)}"
        cv.save(UPLOADS / cv_filename)
    name = request.form["name"].strip()
    career = request.form["career"].strip()
    interest = request.form["interest"].strip()
    skills = request.form["skills"].strip()
    password = request.form["password"].strip()
    if len(password) < 12:
        return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
    try:
        with get_db() as connection:
            existing_user = connection.execute(
                "SELECT id, role FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing_user and existing_user["role"] != "student":
                return jsonify({"error": "Ese correo ya pertenece a otra cuenta."}), 409
            if existing_user:
                connection.execute(
                    "UPDATE users SET name = ?, password_hash = ? WHERE id = ?",
                    (name, generate_password_hash(password), existing_user["id"]),
                )
                user_id = existing_user["id"]
            else:
                cursor = connection.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                    (name, email, generate_password_hash(password)),
                )
                user_id = cursor.lastrowid
            existing_profile = connection.execute(
                "SELECT id, cv_filename FROM students WHERE email = ?", (email,)
            ).fetchone()
            if existing_profile:
                connection.execute(
                    """UPDATE students SET name = ?, career = ?, interest = ?, skills = ?,
                       cv_filename = COALESCE(?, cv_filename), privacy_consent = 1,
                       approval_status = 'pending' WHERE id = ?""",
                    (name, career, interest, skills, cv_filename, existing_profile["id"]),
                )
                profile_id = existing_profile["id"]
            else:
                profile_id = connection.execute(
                    """INSERT INTO students (name, email, career, interest, skills, cv_filename, privacy_consent)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (name, email, career, interest, skills, cv_filename, 1),
                ).lastrowid
            session.clear()
            session
