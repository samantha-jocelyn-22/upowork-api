from pathlib import Path
import csv
import io
import os
import re
import secrets
import sqlite3
import uuid
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY=os.environ.get("UPOWORK_SECRET_KEY") or os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_SECURE=os.environ.get("UPOWORK_HTTPS", "false").lower() == "true",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
                career TEXT NOT NULL, interest TEXT NOT NULL, skills TEXT NOT NULL, cv_filename TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                privacy_consent INTEGER NOT NULL DEFAULT 0,
                approval_status TEXT NOT NULL DEFAULT 'pending', approval_note TEXT
            );
            CREATE TABLE IF NOT EXISTS vacancies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                requirements TEXT DEFAULT '',
                source_url TEXT NOT NULL DEFAULT '',
                opportunity_type TEXT DEFAULT 'empleo',
                career TEXT DEFAULT '',
                location TEXT DEFAULT '',
                mode TEXT DEFAULT 'presencial',
                deadline TEXT DEFAULT '',
                schedule TEXT DEFAULT '',
                support TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_by INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, vacancy_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, vacancy_id)
            );
            CREATE TABLE IF NOT EXISTS suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, category TEXT NOT NULL,
                subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
                message TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS opinions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        student_columns = {row[1] for row in conn.execute("PRAGMA table_info(students)")}
        if "privacy_consent" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN privacy_consent INTEGER NOT NULL DEFAULT 0")
        if "approval_status" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        if "approval_note" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN approval_note TEXT")

        vacancy_columns = {row[1] for row in conn.execute("PRAGMA table_info(vacancies)")}
        
        if "company_id" in vacancy_columns:
            try:
                conn.executescript("""
                    BEGIN TRANSACTION;
                    ALTER TABLE vacancies RENAME TO vacancies_old;
                    CREATE TABLE vacancies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        company_name TEXT NOT NULL DEFAULT '',
                        title TEXT NOT NULL DEFAULT '',
                        description TEXT NOT NULL DEFAULT '',
                        requirements TEXT DEFAULT '',
                        source_url TEXT NOT NULL DEFAULT '',
                        opportunity_type TEXT DEFAULT 'empleo',
                        career TEXT DEFAULT '',
                        location TEXT DEFAULT '',
                        mode TEXT DEFAULT 'presencial',
                        deadline TEXT DEFAULT '',
                        schedule TEXT DEFAULT '',
                        support TEXT DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'active',
                        created_by INTEGER,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO vacancies (id,company_name,title,description,requirements,source_url,opportunity_type,career,location,mode,deadline,schedule,support,status,created_by,created_at)
                    SELECT id,
                           COALESCE(company_name, ''),
                           COALESCE(title, ''),
                           COALESCE(description, ''),
                           COALESCE(requirements, ''),
                           COALESCE(source_url, ''),
                           COALESCE(opportunity_type, 'empleo'),
                           COALESCE(career, ''),
                           COALESCE(location, ''),
                           COALESCE(mode, 'presencial'),
                           COALESCE(deadline, ''),
                           COALESCE(schedule, ''),
                           COALESCE(support, ''),
                           COALESCE(status, 'active'),
                           created_by,
                           CURRENT_TIMESTAMP
                    FROM vacancies_old;
                    DROP TABLE vacancies_old;
                    COMMIT;
                """)
                vacancy_columns = {row[1] for row in conn.execute("PRAGMA table_info(vacancies)")}
            except Exception:
                conn.rollback()
        
        vacancy_migrations = {
            "company_name": "TEXT NOT NULL DEFAULT ''",
            "title": "TEXT NOT NULL DEFAULT ''",
            "description": "TEXT NOT NULL DEFAULT ''",
            "requirements": "TEXT DEFAULT ''",
            "source_url": "TEXT NOT NULL DEFAULT ''",
            "opportunity_type": "TEXT DEFAULT 'empleo'",
            "career": "TEXT DEFAULT ''",
            "location": "TEXT DEFAULT ''",
            "mode": "TEXT DEFAULT 'presencial'",
            "deadline": "TEXT DEFAULT ''",
            "schedule": "TEXT DEFAULT ''",
            "support": "TEXT DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "created_by": "INTEGER",
            "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        }
        for column, definition in vacancy_migrations.items():
            if column not in vacancy_columns:
                conn.execute(f'ALTER TABLE vacancies ADD COLUMN "{column}" {definition}')
        
        conn.execute("UPDATE vacancies SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at=''")
        conn.commit()
    
    ensure_admin_user()


def ensure_admin_user():
    email = (os.environ.get("UPOWORK_ADMIN_EMAIL") or "").strip().lower()
    password = os.environ.get("UPOWORK_ADMIN_PASSWORD") or ""
    if not email or len(password) < 12:
        return
    with get_db() as conn:
        if not conn.execute("SELECT id FROM users WHERE lower(email)=?", (email,)).fetchone():
            conn.execute(
                "INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'teacher')",
                (os.environ.get("UPOWORK_ADMIN_NAME", "Coordinación UPOwork"), email, generate_password_hash(password)),
            )


init_db()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def staff_user():
    user = current_user()
    return bool(user and user["role"] in ("teacher", "admin"))


def csrf_valid():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Inicia sesión primero"}), 401
        return view(*args, **kwargs)
    return wrapped


def require_csrf(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not csrf_valid():
            return jsonify({"error": "La sesión expiró. Recarga la página e inténtalo otra vez."}), 400
        return view(*args, **kwargs)
    return wrapped


def require_staff(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Inicia sesión primero"}), 401
        if not staff_user():
            return jsonify({"error": "No autorizado"}), 403
        return view(*args, **kwargs)
    return wrapped


def safe_url(value):
    parsed = urlparse(value or "")
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


# Pages
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "database": "connected"})
    except sqlite3.Error:
        app.logger.exception("Health check database failure")
        return jsonify({"status": "error", "database": "unavailable"}), 503


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/dashboard")
@app.get("/dashboard.html")
def dashboard_page():
    return render_template("dashboard.html") if current_user() else redirect("/login")


@app.get("/perfil")
@app.get("/perfil.html")
@app.get("/registrar")
def perfil_page():
    return render_template("perfil.html")


@app.route("/registro-personal", methods=["GET", "POST"])
def registro_personal_page():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        codigo = request.form.get("codigo", "").strip()
        
        codigo_valido = os.environ.get("UPOWORK_STAFF_INVITE_CODE", "")
        if not codigo_valido or codigo != codigo_valido:
            return render_template("registro-personal.html",
                                   error="Código de invitación incorrecto.",
                                   csrf_token=session["csrf_token"])
        
        if not all((nombre, email, password)):
            return render_template("registro-personal.html",
                                   error="Todos los campos son obligatorios.",
                                   csrf_token=session["csrf_token"])
        
        if len(password) < 12:
            return render_template("registro-personal.html",
                                   error="La contraseña debe tener al menos 12 caracteres.",
                                   csrf_token=session["csrf_token"])
        
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                    (nombre, email, generate_password_hash(password))
                )
            return redirect("/login?registro=exitoso")
        except sqlite3.IntegrityError:
            return render_template("registro-personal.html",
                                   error="Este correo ya está registrado. Usa uno diferente.",
                                   csrf_token=session["csrf_token"])
    
    return render_template("registro-personal.html", csrf_token=session["csrf_token"])


@app.get("/empresas")
@app.get("/empresas.html")
@app.get("/vacantes")
def empresas_page():
    return render_template("empresas.html")


@app.get("/consejos")
def consejos_page():
    return render_template("consejos.html")


@app.get("/opiniones")
def opiniones_page():
    return render_template("opiniones.html")


@app.get("/sugerencias")
def sugerencias_page():
    return render_template("sugerencias.html") if current_user() else redirect("/login")


@app.get("/aviso-privacidad")
def privacidad_page():
    return render_template("aviso-privacidad.html")


@app.get("/terminos-de-uso")
def terminos_page():
    return render_template("terminos-de-uso.html")


@app.get("/preguntas-frecuentes")
def preguntas_page():
    return render_template("preguntas-frecuentes.html")


@app.get("/contacto")
def contacto_page():
    return render_template("contacto.html")


@app.get("/empresa-registro")
def empresa_registro_page():
    return render_template("empresa-registro.html")


# Authentication / session APIs
@app.get("/api/csrf-token")
def csrf_token_endpoint():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


def authenticate(email, password, selected_role=None):
    with get_db() as conn:
        user = conn.execute
