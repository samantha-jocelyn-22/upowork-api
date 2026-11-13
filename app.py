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
                id INTEGER PRIMARY KEY AUTOINCREMENT, company_name TEXT NOT NULL, title TEXT NOT NULL,
                description TEXT NOT NULL, requirements TEXT DEFAULT '', source_url TEXT NOT NULL,
                opportunity_type TEXT DEFAULT 'empleo', career TEXT DEFAULT '', location TEXT DEFAULT '',
                mode TEXT DEFAULT 'presencial', deadline TEXT DEFAULT '', schedule TEXT DEFAULT '', support TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active', created_by INTEGER,
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
        # Migrate legacy tables in place; do not discard existing records.
        student_columns = {row[1] for row in conn.execute("PRAGMA table_info(students)")}
        if "privacy_consent" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN privacy_consent INTEGER NOT NULL DEFAULT 0")
        if "approval_status" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        if "approval_note" not in student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN approval_note TEXT")

        # Older deployed databases may have a vacancies table without the fields
        # used by the current publication endpoint. CREATE TABLE IF NOT EXISTS does
        # not update an existing table, so add missing columns without deleting rows.
        vacancy_columns = {row[1] for row in conn.execute("PRAGMA table_info(vacancies)")}
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
            "created_at": "TEXT NOT NULL DEFAULT ''",
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
    # Asegurarse de que exista el token CSRF ANTES de mostrar la página
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    
    if request.method == "POST":
        # Procesar el formulario de registro de personal
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        codigo = request.form.get("codigo", "").strip()
        
        # Validar código de invitación
        codigo_valido = os.environ.get("UPOWORK_STAFF_INVITE_CODE", "")
        if not codigo_valido or codigo != codigo_valido:
            return render_template("registro-personal.html", error="Código de invitación incorrecto.")
        
        # Validar campos
        if not all((nombre, email, password)):
            return render_template("registro-personal.html", error="Todos los campos son obligatorios.")
        if len(password) < 12:
            return render_template("registro-personal.html", error="La contraseña debe tener al menos 12 caracteres.")
        
        # Crear usuario en la base de datos
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                    (nombre, email, generate_password_hash(password))
                )
            return redirect("/login?registro=exitoso")
        except sqlite3.IntegrityError:
            return render_template("registro-personal.html", error="Este correo ya está registrado.")
    
    # Si es GET, solo mostramos el formulario
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
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


def authenticate(email, password, selected_role=None):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE lower(email)=?", (email.strip().lower(),)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    if selected_role and selected_role != user["role"] and not (selected_role == "teacher" and user["role"] == "admin"):
        return None
    session.clear()
    session.update(user_id=user["id"], name=user["name"], role=user["role"])
    return user


@app.post("/login")
def login_post():
    user = authenticate(request.form.get("email", ""), request.form.get("password", ""), request.form.get("role") or None)
    if not user:
        return render_template("login.html", error="Correo, contraseña o tipo de cuenta incorrectos."), 401
    return redirect("/dashboard")


@app.post("/api/login")
@require_csrf
def api_login():
    data = request.form if request.form else request.get_json(silent=True) or {}
    user = authenticate(str(data.get("email", "")), str(data.get("password", "")), data.get("role"))
    if not user:
        return jsonify({"error": "Correo, contraseña o tipo de cuenta incorrectos."}), 401
    return jsonify({"message": "Sesión iniciada", "user": {"name": user["name"], "role": user["role"]}})


@app.post("/api/logout")
@require_login
@require_csrf
def api_logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada"})


@app.get("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "No autenticado"}), 401
    return jsonify({"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]})


# Student registration/profile and protected CV download
@app.post("/api/profiles")
@app.post("/api/registro")
@require_csrf
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
    saved_path = None
    if cv and cv.filename:
        if not secure_filename(cv.filename).lower().endswith(".pdf"):
            return jsonify({"error": "El CV debe ser un PDF."}), 400
        if cv.stream.read(5) != b"%PDF-":
            return jsonify({"error": "El archivo no parece ser un PDF válido."}), 400
        cv.stream.seek(0)
        cv_filename = f"{uuid.uuid4().hex}.pdf"
        saved_path = UPLOADS / cv_filename
        cv.save(saved_path)
    try:
        with get_db() as conn:
            cursor = conn.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'student')", (name, email, generate_password_hash(password)))
            conn.execute("INSERT INTO students (name,email,career,interest,skills,cv_filename,privacy_consent) VALUES (?,?,?,?,?,?,1)", (name, email, career, interest, skills, cv_filename))
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        if saved_path:
            saved_path.unlink(missing_ok=True)
        return jsonify({"error": "Este correo ya está registrado."}), 400
    session.clear()
    session.update(user_id=user_id, name=name, role="student")
    return jsonify({"message": "Registro exitoso"}), 201


@app.get("/api/profile")
@require_login
def student_profile():
    with get_db() as conn:
        user = conn.execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
        profile = conn.execute("SELECT * FROM students WHERE lower(email)=lower(?)", (user["email"],)).fetchone() if user else None
    return jsonify(dict(profile) if profile else None)


@app.get("/api/students/<int:student_id>/cv")
@require_login
def download_cv(student_id):
    user = current_user()
    with get_db() as conn:
        row = conn.execute("SELECT email,cv_filename FROM students WHERE id=?", (student_id,)).fetchone()
    if not row or not row["cv_filename"]:
        abort(404)
    if user["role"] not in ("teacher", "admin") and user["email"].lower() != row["email"].lower():
        abort(403)
    return send_from_directory(UPLOADS, row["cv_filename"], mimetype="application/pdf", as_attachment=True, download_name="CV.pdf")


# Vacancies
@app.get("/api/vacancies")
def api_vacancies():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM vacancies WHERE status='active' ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/vacancies")
@require_login
@require_csrf
@require_staff
def create_vacancy():
    data = request.get_json(silent=True) or {}
    company, title, source, description = (str(data.get(k) or "").strip() for k in ("company_name", "title", "source_url", "description"))
    if not all((company, title, source, description)) or not safe_url(source):
        return jsonify({"error": "Empresa, puesto, descripción y enlace http(s) válido son obligatorios."}), 400
    try:
        with get_db() as conn:
            cursor = conn.execute("""INSERT INTO vacancies (company_name,title,description,requirements,source_url,opportunity_type,career,location,mode,deadline,schedule,support,created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (company[:160], title[:200], description[:3000], str(data.get("requirements") or "")[:3000], source[:2048], str(data.get("opportunity_type") or "empleo")[:80], str(data.get("career") or "")[:160], str(data.get("location") or "")[:160], str(data.get("mode") or "presencial")[:40], str(data.get("deadline") or "")[:20], str(data.get("schedule") or "")[:160], str(data.get("support") or "")[:160], session["user_id"]))
    except sqlite3.Error:
        app.logger.exception("Vacancy creation failed")
        return jsonify({"error": "No se pudo guardar la vacante por un problema de base de datos. El equipo administrador debe revisar los logs de Render."}), 500
    return jsonify({"message": "Oportunidad publicada", "id": cursor.lastrowid}), 201


@app.get("/api/my-vacancies")
@require_login
@require_staff
def my_vacancies():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM vacancies ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/vacancies/<int:vacancy_id>")
@require_login
@require_csrf
@require_staff
def update_vacancy(vacancy_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("active", "closed"):
        return jsonify({"error": "Estado de vacante no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE vacancies SET status=? WHERE id=?", (status, vacancy_id))
    return jsonify({"message": "Vacante actualizada"}) if result.rowcount else (jsonify({"error": "Vacante no encontrada."}), 404)


@app.post("/api/vacancies/<int:vacancy_id>/applications")
@require_login
@require_csrf
def apply_vacancy(vacancy_id):
    if current_user()["role"] != "student":
        return jsonify({"error": "Solo los alumnos pueden postularse."}), 403
    with get_db() as conn:
        if not conn.execute("SELECT id FROM vacancies WHERE id=? AND status='active'", (vacancy_id,)).fetchone():
            return jsonify({"error": "Vacante no encontrada o cerrada."}), 404
        try:
            conn.execute("INSERT INTO applications (user_id,vacancy_id) VALUES (?,?)", (session["user_id"], vacancy_id))
        except sqlite3.IntegrityError:
            return jsonify({"message": "Ya te habías postulado a esta vacante."})
    return jsonify({"message": "Postulación registrada"}), 201


@app.get("/api/applications")
@require_login
def api_applications():
    user = current_user()
    with get_db() as conn:
        if user["role"] in ("teacher", "admin"):
            rows = conn.execute("SELECT a.*,v.title,v.company_name,v.source_url,u.name AS student_name,u.email AS student_email FROM applications a JOIN vacancies v ON v.id=a.vacancy_id JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT a.*,v.title,v.company_name,v.source_url FROM applications a JOIN vacancies v ON v.id=a.vacancy_id WHERE a.user_id=? ORDER BY a.created_at DESC", (user["id"],)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/applications/<int:application_id>")
@require_login
@require_csrf
@require_staff
def update_application(application_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("pending", "reviewing", "accepted", "rejected"):
        return jsonify({"error": "Estado de postulación no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE applications SET status=? WHERE id=?", (status, application_id))
    return jsonify({"message": "Postulación actualizada"}) if result.rowcount else (jsonify({"error": "Postulación no encontrada."}), 404)


@app.get("/api/recommendations")
@require_login
def recommendations():
    with get_db() as conn:
        user = conn.execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
        student = conn.execute("SELECT * FROM students WHERE lower(email)=lower(?)", (user["email"],)).fetchone() if user else None
        if not student:
            return jsonify([])
        vacancies = conn.execute("SELECT * FROM vacancies WHERE status='active' ORDER BY created_at DESC").fetchall()
    tokens = set(re.findall(r"[a-záéíóúñ0-9]+", f"{student['career']} {student['interest']} {student['skills']}".lower()))
    results = []
    for vacancy in vacancies:
        if vacancy["career"] and vacancy["career"].lower() != student["career"].lower():
            continue
        text = f"{vacancy['title']} {vacancy['description']} {vacancy['requirements']} {vacancy['career']}".lower()
        matched = any(len(token) > 3 and token in text for token in tokens)
        results.append({**dict(vacancy), "match_reasons": ["Coincide con tu carrera"] + (["Coincide con tus intereses o habilidades"] if matched else [])})
    return jsonify(results[:10])


@app.get("/api/notifications")
@require_login
def notifications():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (session["user_id"],)).fetchall()
    return jsonify([dict(row) for row in rows])


# Students and suggestions for staff dashboard
@app.get("/api/students")
@require_login
@require_staff
def api_students():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM students ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/students/<int:student_id>/approval")
@require_login
@require_csrf
@require_staff
def approve_student(student_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("pending", "approved", "rejected"):
        return jsonify({"error": "Estado de perfil no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE students SET approval_status=? WHERE id=?", (status, student_id))
    return jsonify({"message": "Estado actualizado"}) if result.rowcount else (jsonify({"error": "Perfil no encontrado."}), 404)


@app.delete("/api/students/<int:student_id>")
@require_login
@require_csrf
@require_staff
def delete_student(student_id):
    with get_db() as conn:
        student = conn.execute("SELECT email,cv_filename FROM students WHERE id=?", (student_id,)).fetchone()
        if not student:
            return jsonify({"error": "Perfil no encontrado."}), 404
        user = conn.execute("SELECT id FROM users WHERE lower(email)=lower(?)", (student["email"],)).fetchone()
        if user:
            conn.execute("DELETE FROM applications WHERE user_id=?", (user["id"],))
            conn.execute("DELETE FROM suggestions WHERE user_id=?", (user["id"],))
            conn.execute("DELETE FROM users WHERE id=?", (user["id"],))
        conn.execute("DELETE FROM students WHERE id=?", (student_id,))
    if student["cv_filename"]:
        (UPLOADS / student["cv_filename"]).unlink(missing_ok=True)
    return jsonify({"message": "Perfil eliminado"})


@app.get("/api/suggestions")
@require_login
@require_staff
def api_suggestions():
    with get_db() as conn:
        rows = conn.execute("SELECT s.*,u.name AS student_name FROM suggestions s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/suggestions")
@require_login
@require_csrf
def create_suggestion():
    data = request.get_json(silent=True) or {}
    category, subject, message = (str(data.get(key) or "").strip() for key in ("category", "subject", "message"))
    if not all((category, subject, message)) or len(subject) > 120 or len(message) < 15 or len(message) > 2000:
        return jsonify({"error": "Completa todos los campos; el mensaje debe tener entre 15 y 2,000 caracteres."}), 400
    with get_db() as conn:
        conn.execute("INSERT INTO suggestions (user_id,category,subject,message) VALUES (?,?,?,?)", (session["user_id"], category[:60], subject, message))
    return jsonify({"message": "Sugerencia enviada"}), 201


@app.patch("/api/suggestions/<int:suggestion_id>")
@require_login
@require_csrf
@require_staff
def update_suggestion(suggestion_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("new", "reviewing", "resolved"):
        return jsonify({"error": "Estado de sugerencia no válido."}), 400
    with get_db() as conn:
        result = conn.execute("UPDATE suggestions SET status=? WHERE id=?", (status, suggestion_id))
    return jsonify({"message": "Seguimiento actualizado"}) if result.rowcount else (jsonify({"error": "Sugerencia no encontrada."}), 404)


@app.get("/api/opinions")
def list_opinions():
    with get_db() as conn:
        rows = conn.execute("SELECT id,comment,created_at FROM opinions ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/opinions")
@require_csrf
def create_opinion():
    data = request.get_json(silent=True) or request.form
    comment = str(data.get("comment") or data.get("comentario") or "").strip()
    if not 10 <= len(comment) <= 1200:
        return jsonify({"error": "La opinión debe tener entre 10 y 1,200 caracteres."}), 400
    with get_db() as conn:
        cursor = conn.execute("INSERT INTO opinions (comment) VALUES (?)", (comment,))
        row = conn.execute("SELECT id,comment,created_at FROM opinions WHERE id=?", (cursor.lastrowid,)).fetchone()
    if request.is_json:
        return jsonify({"message": "¡Gracias por compartir tu opinión!", "opinion": dict(row)}), 201
    return redirect("/opiniones?enviada=1", code=303)


@app.get("/api/students/export")
@require_login
@require_staff
def export_students():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Nombre", "Correo", "Carrera", "Interés", "Habilidades", "Estado"])
    with get_db() as conn:
        rows = conn.execute("SELECT name,email,career,interest,skills,approval_status FROM students ORDER BY created_at DESC").fetchall()
    writer.writerows([row[key] for key in ("name", "email", "career", "interest", "skills", "approval_status")] for row in rows)
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
def file_too_large(_error):
    message = "El archivo supera el límite de 5 MB."
    return (jsonify({"error": message}), 413) if request.path.startswith("/api/") else (message, 413)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("UPOWORK_ENV") != "production")
