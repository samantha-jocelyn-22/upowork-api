from pathlib import Path
import csv
import io
import os
import re
import secrets
import sqlite3
import uuid
from datetime import date
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

app = Flask(__name__, static_folder="static", template_folder="templates")
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
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def add_missing_columns(conn, table, columns):
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, declaration in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                career TEXT NOT NULL,
                interest TEXT NOT NULL,
                skills TEXT NOT NULL,
                cv_filename TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                privacy_consent INTEGER NOT NULL DEFAULT 0,
                approval_status TEXT NOT NULL DEFAULT 'pending',
                approval_note TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS vacancies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                requirements TEXT DEFAULT '',
                source_url TEXT NOT NULL,
                opportunity_type TEXT DEFAULT 'empleo',
                career TEXT DEFAULT '',
                location TEXT DEFAULT '',
                mode TEXT DEFAULT 'presencial',
                deadline TEXT DEFAULT '',
                schedule TEXT DEFAULT '',
                support TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_by INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                vacancy_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, vacancy_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(vacancy_id) REFERENCES vacancies(id)
            );
            CREATE TABLE IF NOT EXISTS suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                read_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        # Upgrade the older SQLite tables in place without deleting existing records.
        add_missing_columns(conn, "users", {
            "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        })
        add_missing_columns(conn, "students", {
            "user_id": "INTEGER",
            "name": "TEXT NOT NULL DEFAULT ''",
            "email": "TEXT NOT NULL DEFAULT ''",
            "career": "TEXT NOT NULL DEFAULT ''",
            "interest": "TEXT NOT NULL DEFAULT ''",
            "skills": "TEXT NOT NULL DEFAULT ''",
            "cv_filename": "TEXT",
            "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "privacy_consent": "INTEGER NOT NULL DEFAULT 0",
            "approval_status": "TEXT NOT NULL DEFAULT 'pending'",
            "approval_note": "TEXT",
        })
        conn.execute("UPDATE students SET user_id = (SELECT id FROM users WHERE lower(users.email) = lower(students.email)) WHERE user_id IS NULL")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_students_user_id ON students(user_id) WHERE user_id IS NOT NULL")
        add_missing_columns(conn, "vacancies", {
            "requirements": "TEXT DEFAULT ''", "source_url": "TEXT NOT NULL DEFAULT ''",
            "opportunity_type": "TEXT DEFAULT 'empleo'", "career": "TEXT DEFAULT ''",
            "location": "TEXT DEFAULT ''", "mode": "TEXT DEFAULT 'presencial'",
            "deadline": "TEXT DEFAULT ''", "schedule": "TEXT DEFAULT ''", "support": "TEXT DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'active'", "created_by": "INTEGER",
            "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        })
        add_missing_columns(conn, "applications", {
            "user_id": "INTEGER", "vacancy_id": "INTEGER", "status": "TEXT NOT NULL DEFAULT 'pending'",
            "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        })
        add_missing_columns(conn, "suggestions", {
            "user_id": "INTEGER", "category": "TEXT NOT NULL DEFAULT 'general'",
            "subject": "TEXT NOT NULL DEFAULT ''", "message": "TEXT NOT NULL DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'new'", "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        })
        add_missing_columns(conn, "notifications", {
            "user_id": "INTEGER", "title": "TEXT NOT NULL DEFAULT ''", "message": "TEXT NOT NULL DEFAULT ''",
            "read_at": "TEXT", "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        })
        conn.commit()
    ensure_admin_user()


def ensure_admin_user():
    # Never install a publicly-known password. Configure both secrets in the hosting dashboard.
    email = (os.environ.get("UPOWORK_ADMIN_EMAIL") or "").strip().lower()
    password = os.environ.get("UPOWORK_ADMIN_PASSWORD") or ""
    if not email or len(password) < 12:
        return
    name = os.environ.get("UPOWORK_ADMIN_NAME") or "Coordinación UPOwork"
    with get_db() as conn:
        found = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not found:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                (name, email, generate_password_hash(password)),
            )


init_db()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required_page(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Inicia sesión primero"}), 401
        return view(*args, **kwargs)
    return wrapped


def staff_required():
    user = current_user()
    return bool(user and user["role"] in ("teacher", "admin"))


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = session.get("csrf_token")
        supplied = request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            return jsonify({"error": "La sesión expiró o la solicitud no es válida. Recarga la página e inténtalo otra vez."}), 400
        return view(*args, **kwargs)
    return wrapped


def safe_url(value):
    parsed = urlparse(value or "")
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


# Pages
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    return redirect("/dashboard") if current_user() else render_template("login.html")


@app.get("/dashboard")
@app.get("/dashboard.html")
@login_required_page
def dashboard_page():
    return render_template("dashboard.html")


@app.get("/perfil")
@app.get("/perfil.html")
@app.get("/registrar")
def perfil_page():
    # Registration must be reachable before a student has an account.
    return render_template("perfil.html")


@app.get("/registro-personal")
@app.get("/registro-personal.html")
def registro_personal_page():
    return render_template("registro-personal.html")


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
@login_required_page
def sugerencias_page():
    return render_template("sugerencias.html")


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


# Authentication
@app.get("/api/csrf-token")
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


def authenticate(email, password, selected_role=None):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (email.lower(),)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    if selected_role and selected_role != user["role"] and not (selected_role == "teacher" and user["role"] == "admin"):
        return None
    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    return user


@app.post("/login")
def login_post():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role") or None
    user = authenticate(email, password, role)
    if not user:
        return render_template("login.html", error="Revisa el correo, la contraseña y el tipo de cuenta seleccionados."), 401
    return redirect("/dashboard")


@app.post("/api/login")
@csrf_required
def api_login():
    data = request.form if request.form else request.get_json(silent=True) or {}
    user = authenticate(str(data.get("email", "")).strip(), str(data.get("password", "")), data.get("role"))
    if not user:
        return jsonify({"error": "Revisa el correo, la contraseña y el tipo de cuenta seleccionados."}), 401
    return jsonify({"message": "Sesión iniciada", "user": {"id": user["id"], "name": user["name"], "role": user["role"]}})


@app.post("/api/logout")
@api_login_required
@csrf_required
def api_logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada"})


@app.post("/registro-personal")
def registro_personal_post():
    name = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    invite_code = request.form.get("codigo", "")
    configured_code = os.environ.get("UPOWORK_STAFF_INVITE_CODE") or ""
    if not configured_code or not secrets.compare_digest(invite_code, configured_code):
        return render_template("registro-personal.html", error="El código de invitación no es válido o no está configurado."), 400
    if not name or not email or len(password) < 12:
        return render_template("registro-personal.html", error="Completa los campos; la contraseña debe tener al menos 12 caracteres."), 400
    with get_db() as conn:
        try:
            conn.execute("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')", (name, email, generate_password_hash(password)))
        except sqlite3.IntegrityError:
            return render_template("registro-personal.html", error="Este correo ya está registrado."), 400
    return redirect("/login")


# Student registration/profile and CV upload
@app.post("/api/profiles")
@app.post("/api/registro")
@csrf_required
def register_profile():
    name = (request.form.get("name") or request.form.get("nombre") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    career = (request.form.get("career") or request.form.get("carrera") or "").strip()
    interest = (request.form.get("interest") or request.form.get("intereses") or "").strip()
    skills = (request.form.get("skills") or request.form.get("habilidades") or "").strip()
    password = request.form.get("password") or request.form.get("contrasena") or ""
    consent = request.form.get("privacy_consent") in ("1", "on", "true") or request.form.get("acepta_privacidad") in ("1", "on", "true")
    if not all((name, email, career, interest, skills, password)):
        return jsonify({"error": "Todos los campos obligatorios deben completarse."}), 400
    if len(password) < 12:
        return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
    if not consent:
        return jsonify({"error": "Debes aceptar el aviso de privacidad."}), 400

    cv = request.files.get("cv")
    cv_filename = None
    if cv and cv.filename:
        original = secure_filename(cv.filename)
        if not original.lower().endswith(".pdf"):
            return jsonify({"error": "El CV debe ser un archivo PDF."}), 400
        # Check PDF signature instead of trusting the extension or browser MIME type.
        header = cv.stream.read(5)
        cv.stream.seek(0)
        if header != b"%PDF-":
            return jsonify({"error": "El archivo seleccionado no parece ser un PDF válido."}), 400
        cv_filename = f"{uuid.uuid4().hex}.pdf"

    saved_path = UPLOADS / cv_filename if cv_filename else None
    if saved_path:
        cv.save(saved_path)
    try:
        with get_db() as conn:
            cur = conn.execute("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')", (name, email, generate_password_hash(password)))
            user_id = cur.lastrowid
            conn.execute("INSERT INTO students (user_id, name, email, career, interest, skills, cv_filename, privacy_consent) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (user_id, name, email, career, interest, skills, cv_filename))
            conn.commit()
    except sqlite3.IntegrityError:
        if saved_path and saved_path.exists():
            saved_path.unlink()
        return jsonify({"error": "Este correo ya está registrado."}), 400

    session.clear()
    session["user_id"] = user_id
    session["name"] = name
    session["role"] = "student"
    return jsonify({"message": "Registro exitoso"})


@app.get("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "No autenticado"}), 401
    return jsonify({"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]})


@app.get("/api/profile")
@api_login_required
def api_profile():
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM students WHERE user_id = ? ORDER BY id DESC LIMIT 1", (session["user_id"],)).fetchone()
    return jsonify(dict(profile) if profile else None)


@app.get("/api/students/<int:student_id>/cv")
@api_login_required
def student_cv(student_id):
    user = current_user()
    with get_db() as conn:
        student = conn.execute("SELECT user_id, cv_filename FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student or not student["cv_filename"]:
        abort(404)
    if user["role"] not in ("teacher", "admin") and student["user_id"] != user["id"]:
        abort(403)
    return send_from_directory(UPLOADS, student["cv_filename"], mimetype="application/pdf", as_attachment=True, download_name="CV.pdf")


# Vacancies, applications, and dashboard data
@app.get("/api/vacancies")
def api_vacancies():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM vacancies WHERE status = 'active' ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/vacancies")
@api_login_required
@csrf_required
def create_vacancy():
    if not staff_required():
        return jsonify({"error": "Solo personal autorizado puede publicar vacantes."}), 403
    data = request.get_json(silent=True) or {}
    company, title, source, description = (str(data.get(k) or "").strip() for k in ("company_name", "title", "source_url", "description"))
    if not all((company, title, source, description)) or not safe_url(source):
        return jsonify({"error": "Empresa, título, descripción y un enlace http(s) válido son obligatorios."}), 400
    if len(company) > 160 or len(title) > 200 or len(description) > 3000:
        return jsonify({"error": "Revisa el largo de los campos."}), 400
    with get_db() as conn:
        cur = conn.execute("""INSERT INTO vacancies (company_name,title,description,requirements,source_url,opportunity_type,career,location,mode,deadline,schedule,support,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (company, title, description, str(data.get("requirements") or "")[:3000], source, str(data.get("opportunity_type") or "empleo")[:80], str(data.get("career") or "")[:160], str(data.get("location") or "")[:160], str(data.get("mode") or "presencial")[:40], str(data.get("deadline") or "")[:20], str(data.get("schedule") or "")[:160], str(data.get("support") or "")[:160], session["user_id"]))
        vacancy_id = cur.lastrowid
    return jsonify({"message": "Oportunidad publicada", "id": vacancy_id}), 201


@app.get("/api/my-vacancies")
@api_login_required
def my_vacancies():
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM vacancies ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/api/vacancies/<int:vacancy_id>")
@api_login_required
@csrf_required
def update_vacancy(vacancy_id):
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("active", "closed"):
        return jsonify({"error": "Estado de vacante no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE vacancies SET status = ? WHERE id = ?", (status, vacancy_id))
    if not result.rowcount:
        return jsonify({"error": "Vacante no encontrada."}), 404
    return jsonify({"message": "Vacante actualizada"})


@app.post("/api/vacancies/<int:vacancy_id>/applications")
@api_login_required
@csrf_required
def apply_vacancy(vacancy_id):
    user = current_user()
    if user["role"] != "student":
        return jsonify({"error": "Solo los alumnos pueden postularse."}), 403
    with get_db() as conn:
        vacancy = conn.execute("SELECT id FROM vacancies WHERE id = ? AND status = 'active'", (vacancy_id,)).fetchone()
        if not vacancy:
            return jsonify({"error": "Vacante no encontrada o cerrada."}), 404
        try:
            conn.execute("INSERT INTO applications (user_id, vacancy_id) VALUES (?, ?)", (user["id"], vacancy_id))
        except sqlite3.IntegrityError:
            return jsonify({"message": "Ya te habías postulado a esta vacante."})
    return jsonify({"message": "Postulación registrada"}), 201


@app.get("/api/applications")
@api_login_required
def api_applications():
    user = current_user()
    with get_db() as conn:
        if user["role"] in ("teacher", "admin"):
            rows = conn.execute("""SELECT a.*, v.title, v.company_name, v.source_url, u.name AS student_name, u.email AS student_email
                FROM applications a JOIN vacancies v ON v.id=a.vacancy_id JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC""").fetchall()
        else:
            rows = conn.execute("""SELECT a.*, v.title, v.company_name, v.source_url
                FROM applications a JOIN vacancies v ON v.id=a.vacancy_id WHERE a.user_id=? ORDER BY a.created_at DESC""", (user["id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/api/applications/<int:application_id>")
@api_login_required
@csrf_required
def update_application(application_id):
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("pending", "reviewing", "accepted", "rejected"):
        return jsonify({"error": "Estado de postulación no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE applications SET status=? WHERE id=?", (status, application_id))
    if not result.rowcount:
        return jsonify({"error": "Postulación no encontrada."}), 404
    return jsonify({"message": "Postulación actualizada"})


@app.get("/api/recommendations")
@api_login_required
def recommendations():
    with get_db() as conn:
        student = conn.execute("SELECT * FROM students WHERE user_id=? ORDER BY id DESC LIMIT 1", (session["user_id"],)).fetchone()
        if not student:
            return jsonify([])
        rows = conn.execute("SELECT * FROM vacancies WHERE status='active' ORDER BY created_at DESC").fetchall()
    tokens = set(re.findall(r"[a-záéíóúñ0-9]+", f"{student['career']} {student['interest']} {student['skills]}".lower()))
    results = []
    for vacancy in rows:
        if vacancy["career"] and vacancy["career"].lower() != student["career"].lower():
            continue
        text = f"{vacancy['title']} {vacancy['description']} {vacancy['requirements']} {vacancy['career']}".lower()
        hits = [token for token in tokens if len(token) > 3 and token in text]
        results.append({**dict(vacancy), "match_reasons": ["Coincide con tu carrera"] + (["Coincide con tus intereses o habilidades"] if hits else [])})
    return jsonify(results[:10])


@app.get("/api/notifications")
@api_login_required
def notifications():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (session["user_id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


# Student directory, suggestions and basic moderation
@app.get("/api/students")
@api_login_required
def api_students():
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    with get_db() as conn:
        rows = conn.execute("SELECT s.*, u.email FROM students s LEFT JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/api/students/<int:student_id>/approval")
@api_login_required
@csrf_required
def approve_student(student_id):
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("pending", "approved", "rejected"):
        return jsonify({"error": "Estado no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE students SET approval_status=? WHERE id=?", (status, student_id))
    if not result.rowcount:
        return jsonify({"error": "Perfil no encontrado."}), 404
    return jsonify({"message": "Estado actualizado"})


@app.delete("/api/students/<int:student_id>")
@api_login_required
@csrf_required
def delete_student(student_id):
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    with get_db() as conn:
        row = conn.execute("SELECT user_id, cv_filename FROM students WHERE id=?", (student_id,)).fetchone()
        if not row:
            return jsonify({"error": "Perfil no encontrado."}), 404
        conn.execute("DELETE FROM applications WHERE user_id=?", (row["user_id"],))
        conn.execute("DELETE FROM suggestions WHERE user_id=?", (row["user_id"],))
        conn.execute("DELETE FROM students WHERE id=?", (student_id,))
        conn.execute("DELETE FROM users WHERE id=? AND role='student'", (row["user_id"],))
    if row["cv_filename"]:
        (UPLOADS / row["cv_filename"]).unlink(missing_ok=True)
    return jsonify({"message": "Perfil eliminado"})


@app.get("/api/suggestions")
@api_login_required
def api_suggestions():
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    with get_db() as conn:
        rows = conn.execute("SELECT s.*, u.name AS student_name FROM suggestions s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/suggestions")
@api_login_required
@csrf_required
def create_suggestion():
    user = current_user()
    data = request.get_json(silent=True) or {}
    category, subject, message = (str(data.get(key) or "").strip() for key in ("category", "subject", "message"))
    if not all((category, subject, message)) or len(subject) > 120 or len(message) < 15 or len(message) > 2000:
        return jsonify({"error": "Completa tema y título; el mensaje debe tener entre 15 y 2,000 caracteres."}), 400
    with get_db() as conn:
        conn.execute("INSERT INTO suggestions (user_id, category, subject, message) VALUES (?,?,?,?)", (user["id"], category[:60], subject, message))
    return jsonify({"message": "Sugerencia enviada"}), 201


@app.patch("/api/suggestions/<int:suggestion_id>")
@api_login_required
@csrf_required
def update_suggestion(suggestion_id):
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("new", "reviewing", "resolved"):
        return jsonify({"error": "Estado no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE suggestions SET status=? WHERE id=?", (status, suggestion_id))
    if not result.rowcount:
        return jsonify({"error": "Sugerencia no encontrada."}), 404
    return jsonify({"message": "Seguimiento actualizado"})


@app.get("/api/students/export")
@api_login_required
def export_students():
    if not staff_required():
        return jsonify({"error": "No autorizado"}), 403
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Nombre", "Correo", "Carrera", "Interés", "Habilidades", "Estado"])
    with get_db() as conn:
        rows = conn.execute("SELECT name,email,career,interest,skills,approval_status FROM students ORDER BY created_at DESC").fetchall()
    for row in rows:
        writer.writerow([row["name"], row["email"], row["career"], row["interest"], row["skills"], row["approval_status"]])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=alumnos-upowork.csv"})


@app.get("/styles.css")
def root_styles():
    return send_from_directory("static", "styles.css")


@app.get("/script.js")
def root_script():
    return send_from_directory("static", "script.js")


@app.get("/dashboard.js")
def root_dashboard_script():
    return send_from_directory("static", "dashboard.js")


@app.get("/suggestions.js")
def root_suggestions_script():
    return send_from_directory("static", "suggestions.js")


@app.get("/upowork-logo.svg")
def root_logo():
    return send_from_directory("static", "upowork-logo.svg")


@app.errorhandler(413)
def too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "El archivo supera el límite de 5 MB."}), 413
    return "El archivo supera el límite de 5 MB.", 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("UPOWORK_ENV") != "production")
