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

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
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
                vacancies INTEGER NOT NULL DEFAULT 0
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
            """
        )
        # Migrate databases created by the first prototype without breaking demo data.
        student_columns = {row["name"] for row in connection.execute("PRAGMA table_info(students)")}
        for definition in ("privacy_consent INTEGER NOT NULL DEFAULT 0", "approval_status TEXT NOT NULL DEFAULT 'pending'", "approval_note TEXT"):
            column = definition.split()[0]
            if column not in student_columns:
                connection.execute(f"ALTER TABLE students ADD COLUMN {definition}")
        company_columns = {row["name"] for row in connection.execute("PRAGMA table_info(companies)")}
        if "user_id" not in company_columns:
            connection.execute("ALTER TABLE companies ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if "is_demo" not in company_columns:
            connection.execute("ALTER TABLE companies ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0")
        if "approval_status" not in company_columns:
            connection.execute("ALTER TABLE companies ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        connection.execute(
            """UPDATE companies SET is_demo = 1
               WHERE name IN ('Nube Digital', 'Grupo Horizonte', 'Estudio Norte', 'Empresa aliada')
                  OR user_id IN (SELECT id FROM users WHERE email IN
                     ('empresa@upowork.mx', 'alumno@upowork.mx', 'maestro@upowork.mx'))"""
        )
        demo_emails = ("alumno@upowork.mx", "maestro@upowork.mx", "empresa@upowork.mx")
        connection.executemany(
            "DELETE FROM students WHERE email = ?",
            [(email,) for email in demo_emails],
        )
        connection.execute(
            """DELETE FROM companies WHERE user_id IN
               (SELECT id FROM users WHERE email IN (?, ?, ?))""",
            demo_emails,
        )
        connection.executemany(
            "DELETE FROM users WHERE email = ?",
            [(email,) for email in demo_emails],
        )
        vacancy_columns = {row["name"] for row in connection.execute("PRAGMA table_info(vacancies)")}
        if "career" not in vacancy_columns:
            connection.execute("ALTER TABLE vacancies ADD COLUMN career TEXT")
        for definition in (
            "opportunity_type TEXT NOT NULL DEFAULT 'empleo'",
            "deadline TEXT",
            "schedule TEXT",
            "support TEXT",
            "source_url TEXT",
        ):
            column = definition.split()[0]
            if column not in vacancy_columns:
                connection.execute(f"ALTER TABLE vacancies ADD COLUMN {definition}")
        admin_email = os.environ.get("UPOWORK_ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("UPOWORK_ADMIN_PASSWORD", "")
        if admin_email and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", admin_email) and len(admin_password) >= 12:
            existing_admin = connection.execute(
                "SELECT id FROM users WHERE email = ?", (admin_email,)
            ).fetchone()
            if not existing_admin:
                connection.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                    (
                        os.environ.get("UPOWORK_ADMIN_NAME", "Administración UPOwork"),
                        admin_email,
                        generate_password_hash(admin_password),
                    ),
                )


def valid_pdf(file):
    if not file or not file.filename or not file.filename.lower().endswith(".pdf"):
        return False
    signature = file.stream.read(5)
    file.stream.seek(0)
    return signature == b"%PDF-"


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


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
        return jsonify({"error": "El acceso de empresas ya no está disponible. Consulta las vacantes publicadas por la universidad."}), 403
    with get_db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or user["role"] != requested_role or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401
    csrf = secrets.token_urlsafe(32)
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = csrf
    return jsonify({"name": user["name"], "role": user["role"]})


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.post("/api/companies/register")
@app.post("/api/company/register")
def register_company():
    return jsonify({"error": "El registro de empresas está desactivado. La universidad publica vacantes verificadas con un enlace al anuncio original."}), 410


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada."})


@app.get("/api/me")
@login_required
def current_user():
    with get_db() as connection:
        user = connection.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    return jsonify(dict(user))


@app.patch("/api/account/password")
@login_required
def change_password():
    data = request.get_json(silent=True) or request.form
    current = str(data.get("current_password", ""))
    replacement = str(data.get("new_password", ""))
    if len(replacement) < 12:
        return jsonify({"error": "La nueva contraseña debe tener al menos 12 caracteres."}), 400
    with get_db() as connection:
        user = session_user(connection)
        if not user or not check_password_hash(user["password_hash"], current):
            return jsonify({"error": "La contraseña actual no es correcta."}), 400
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(replacement), user["id"]),
        )
    return jsonify({"message": "Contraseña actualizada correctamente."})


@app.get("/<path:filename>")
def frontend_file(filename):
    return send_from_directory(BASE_DIR, filename)


@app.get("/api/companies")
def companies():
    return jsonify({"error": "El directorio de empresas fue sustituido por el listado de vacantes."}), 410


@app.get("/api/my-company")
@login_required
def my_company():
    with get_db() as connection:
        user = session_user(connection)
        company = company_for_user(connection, user["id"]) if user and user["role"] == "company" else None
    if not company:
        return jsonify({"error": "No hay una empresa vinculada a esta cuenta."}), 404
    return jsonify({
        "id": company["id"],
        "name": company["name"],
        "approval_status": company["approval_status"],
    })


@app.get("/api/companies/admin")
@login_required
def admin_companies():
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "Solo el personal autorizado puede revisar empresas."}), 403
        rows = connection.execute(
            "SELECT id, name, area, mode, approval_status FROM companies WHERE is_demo = 0 ORDER BY name"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/companies/<int:company_id>/approval")
@login_required
def approve_company(company_id):
    data = request.get_json(silent=True) or request.form
    status = str(data.get("status", "")).strip()
    if status not in {"pending", "approved", "rejected"}:
        return jsonify({"error": "Estado de empresa no válido."}), 400
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "Solo un maestro puede aprobar empresas."}), 403
        company = connection.execute(
            "SELECT id FROM companies WHERE id = ? AND is_demo = 0", (company_id,)
        ).fetchone()
        if not company:
            return jsonify({"error": "La empresa no existe."}), 404
        connection.execute(
            "UPDATE companies SET approval_status = ? WHERE id = ?",
            (status, company_id),
        )
    return jsonify({"id": company_id, "approval_status": status})


def session_user(connection):
    return connection.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def company_for_user(connection, user_id):
    return connection.execute("SELECT * FROM companies WHERE user_id = ?", (user_id,)).fetchone()


def add_notification(connection, user_id, title, message):
    connection.execute(
        "INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)",
        (user_id, title, message),
    )


@app.get("/api/vacancies")
def list_vacancies():
    company_id = request.args.get("company_id")
    query = """
        SELECT v.*, c.name AS company_name, c.area AS company_area
        FROM vacancies v JOIN companies c ON c.id = v.company_id
    """
    params = ()
    query += """ WHERE v.status = 'open' AND v.source_url IS NOT NULL AND c.user_id IS NULL
                 AND c.is_demo = 0 AND c.approval_status = 'approved'
                 AND (v.deadline IS NULL OR v.deadline = '' OR v.deadline >= date('now'))"""
    if company_id:
        query += " AND v.company_id = ?"
        params = (company_id,)
    query += " ORDER BY v.created_at DESC"
    with get_db() as connection:
        rows = connection.execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/my-vacancies")
@login_required
def my_vacancies():
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "Solo el personal autorizado puede administrar vacantes."}), 403
        query = """SELECT v.*, c.name AS company_name FROM vacancies v
                   JOIN companies c ON c.id = v.company_id"""
        rows = connection.execute(query + " ORDER BY v.created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/vacancies")
@login_required
def create_vacancy():
    data = request.get_json(silent=True) or request.form
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "Solo el personal autorizado puede publicar vacantes."}), 403
        company_name = str(data.get("company_name", "")).strip()
        source_url = str(data.get("source_url", "")).strip()
        try:
            parsed_url = urlsplit(source_url)
        except ValueError:
            return jsonify({"error": "El enlace de la vacante no tiene un formato válido."}), 400
        if (
            not company_name
            or len(company_name) > 160
            or len(source_url) > 2048
            or parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
        ):
            return jsonify({"error": "Indica el nombre de la empresa y un enlace público válido que empiece con https:// o http://."}), 400
        title, description = str(data.get("title", "")).strip(), str(data.get("description", "")).strip()
        if not title or not description:
            return jsonify({"error": "Título y descripción son obligatorios."}), 400
        company = connection.execute(
            """SELECT id FROM companies
               WHERE lower(name) = lower(?) AND user_id IS NULL AND is_demo = 0
               ORDER BY id LIMIT 1""",
            (company_name,),
        ).fetchone()
        if company:
            company_id = company["id"]
            connection.execute(
                "UPDATE companies SET approval_status = 'approved' WHERE id = ?",
                (company_id,),
            )
        else:
            company_id = connection.execute(
                """INSERT INTO companies
                   (name, area, mode, distance, vacancies, user_id, is_demo, approval_status)
                   VALUES (?, 'Vacante externa', ?, ?, 0, NULL, 0, 'approved')""",
                (
                    company_name,
                    str(data.get("mode", "presencial")).strip(),
                    str(data.get("location", "")).strip() or "No especificada",
                ),
            ).lastrowid
        vacancy_id = connection.execute(
            """INSERT INTO vacancies
               (company_id, title, description, mode, location, requirements, career,
                opportunity_type, deadline, schedule, support, source_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (company_id, title, description, str(data.get("mode", "presencial")).strip(),
             str(data.get("location", "")).strip(), str(data.get("requirements", "")).strip(),
             str(data.get("career", "")).strip(),
             str(data.get("opportunity_type", "empleo")).strip(),
             str(data.get("deadline", "")).strip() or None,
             str(data.get("schedule", "")).strip(),
             str(data.get("support", "")).strip(), source_url),
        ).lastrowid
        connection.execute("UPDATE companies SET vacancies = (SELECT COUNT(*) FROM vacancies WHERE company_id = ? AND status = 'open') WHERE id = ?", (company_id, company_id))
        vacancy = connection.execute(
            """SELECT v.*, c.name AS company_name FROM vacancies v
               JOIN companies c ON c.id = v.company_id WHERE v.id = ?""",
            (vacancy_id,),
        ).fetchone()
    return jsonify(dict(vacancy)), 201


@app.route("/api/vacancies/<int:vacancy_id>", methods=["PUT", "PATCH", "DELETE"])
@login_required
def modify_vacancy(vacancy_id):
    with get_db() as connection:
        user = session_user(connection)
        vacancy = connection.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
        if not vacancy:
            return jsonify({"error": "La vacante no existe."}), 404
        if not user or user["role"] != "teacher":
            return jsonify({"error": "No tienes permisos para administrar esta vacante."}), 403
        if request.method == "DELETE":
            connection.execute("DELETE FROM vacancies WHERE id = ?", (vacancy_id,))
            return jsonify({"message": "Vacante eliminada."})
        data = request.get_json(silent=True) or request.form
        fields = ["title", "description", "mode", "location", "requirements", "status", "source_url"]
        updates = [(field, str(data[field]).strip()) for field in fields if field in data]
        if not updates:
            return jsonify(dict(vacancy))
        if any(field in ("title", "description") and not value for field, value in updates):
            return jsonify({"error": "Título y descripción no pueden estar vacíos."}), 400
        for field, value in updates:
            if field == "source_url":
                try:
                    parsed_url = urlsplit(value)
                except ValueError:
                    return jsonify({"error": "El enlace de la vacante no tiene un formato válido."}), 400
                if (
                    len(value) > 2048
                    or parsed_url.scheme not in {"http", "https"}
                    or not parsed_url.hostname
                    or parsed_url.username
                    or parsed_url.password
                ):
                    return jsonify({"error": "El enlace debe ser público y comenzar con https:// o http://."}), 400
        connection.execute("UPDATE vacancies SET " + ", ".join(f"{field} = ?" for field, _ in updates) + " WHERE id = ?", [value for _, value in updates] + [vacancy_id])
        updated = connection.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
    return jsonify(dict(updated))


@app.post("/api/vacancies/<int:vacancy_id>/applications")
@login_required
def apply_vacancy(vacancy_id):
    data = request.get_json(silent=True) or request.form
    with get_db() as connection:
        user = session_user(connection)
        student = connection.execute("SELECT * FROM students WHERE email = ?", (user["email"],)).fetchone() if user and user["role"] == "student" else None
        vacancy = connection.execute(
            """SELECT v.* FROM vacancies v JOIN companies c ON c.id = v.company_id
               WHERE v.id = ? AND v.status = 'open' AND c.approval_status = 'approved'
                 AND (v.deadline IS NULL OR v.deadline = '' OR v.deadline >= date('now'))""",
            (vacancy_id,),
        ).fetchone()
        if not student or not vacancy:
            return jsonify({"error": "Solo un alumno puede postularse a una vacante abierta."}), 403
        if vacancy["source_url"]:
            return jsonify({"error": "Esta vacante se gestiona en el portal de empleo de origen. Usa su enlace para consultar los detalles y postularte."}), 409
        try:
            application_id = connection.execute(
                "INSERT INTO applications (vacancy_id, student_id, cover_note) VALUES (?, ?, ?)",
                (vacancy_id, student["id"], str(data.get("cover_note", "")).strip()),
            ).lastrowid
        except sqlite3.IntegrityError:
            return jsonify({"error": "Ya te postulaste a esta vacante."}), 409
    return jsonify({"id": application_id, "status": "pending"}), 201


@app.get("/api/applications")
@login_required
def list_applications():
    with get_db() as connection:
        user = session_user(connection)
        if user["role"] == "student":
            query, params = "WHERE s.email = ?", (user["email"],)
        elif user["role"] == "teacher":
            query, params = "", ()
        else:
            return jsonify({"error": "Rol no autorizado."}), 403
        rows = connection.execute(
            """SELECT a.*, v.title, v.company_id, c.name AS company_name,
                      s.id AS student_id, s.name AS student_name, s.email AS student_email
               FROM applications a JOIN vacancies v ON v.id = a.vacancy_id
               JOIN companies c ON c.id = v.company_id JOIN students s ON s.id = a.student_id """
            + query + " ORDER BY a.created_at DESC", params).fetchall()
    return jsonify([dict(row) for row in rows])


def recommendation_score(profile, vacancy):
    """Score an open vacancy against the student's declared information."""
    def words(value):
        return {
            word for word in re.findall(r"[a-záéíóúüñ]{4,}", (value or "").lower())
            if word not in {"para", "como", "esta", "este", "desde", "entre", "sobre"}
        }

    vacancy_text = " ".join(
        (vacancy["title"], vacancy["description"], vacancy["requirements"])
    )
    score = 0
    reasons = []
    if vacancy["career"] and vacancy["career"].lower() == profile["career"].lower():
        score += 6
        reasons.append("Tu carrera coincide con la vacante")
    elif vacancy["career"]:
        return 0, []

    interest_words = words(profile["interest"])
    vacancy_words = words(vacancy_text)
    interest_matches = interest_words & vacancy_words
    if interest_matches:
        score += 2
        reasons.append("Se relaciona con lo que estás buscando")

    skill_matches = words(profile["skills"]) & vacancy_words
    if skill_matches:
        score += min(3, len(skill_matches))
        reasons.append("Menciona habilidades de tu perfil")
    return score, reasons


@app.get("/api/recommendations")
@login_required
def recommendations():
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "student":
            return jsonify({"error": "Solo un alumno puede consultar recomendaciones."}), 403
        profile = connection.execute(
            "SELECT * FROM students WHERE email = ?", (user["email"],)
        ).fetchone()
        if not profile:
            return jsonify([])
        vacancies = connection.execute(
            """SELECT v.*, c.name AS company_name, c.area AS company_area
               FROM vacancies v JOIN companies c ON c.id = v.company_id
               WHERE v.status = 'open' AND v.source_url IS NOT NULL
                 AND c.user_id IS NULL AND c.is_demo = 0 AND c.approval_status = 'approved'
                 AND (v.deadline IS NULL OR v.deadline = '' OR v.deadline >= date('now'))
               ORDER BY v.created_at DESC"""
        ).fetchall()
        result = []
        for vacancy in vacancies:
            score, reasons = recommendation_score(profile, vacancy)
            if score >= 2:
                item = dict(vacancy)
                item["match_score"] = score
                item["match_reasons"] = reasons
                result.append(item)
    result.sort(key=lambda item: (-item["match_score"], item["created_at"]))
    return jsonify(result[:6])


@app.patch("/api/applications/<int:application_id>")
@login_required
def update_application(application_id):
    data = request.get_json(silent=True) or request.form
    status = str(data.get("status", "")).strip()
    if status not in {"pending", "reviewing", "accepted", "rejected", "withdrawn"}:
        return jsonify({"error": "Estado de postulación no válido."}), 400
    with get_db() as connection:
        user = session_user(connection)
        application = connection.execute(
            """SELECT a.*, v.company_id, s.email FROM applications a
               JOIN vacancies v ON v.id = a.vacancy_id JOIN students s ON s.id = a.student_id
               WHERE a.id = ?""", (application_id,)).fetchone()
        owns_application = user["role"] == "student" and application and application["email"] == user["email"]
        if not application or (user["role"] != "teacher" and not owns_application):
            return jsonify({"error": "No tienes permisos para actualizar esta postulación."}), 403
        if user["role"] == "student" and status != "withdrawn":
            return jsonify({"error": "Un alumno solo puede retirar su postulación."}), 403
        connection.execute("UPDATE applications SET status = ? WHERE id = ?", (status, application_id))
        student_user = connection.execute(
            "SELECT id FROM users WHERE email = ?", (application["email"],)
        ).fetchone()
        if student_user and user["role"] != "student":
            add_notification(
                connection,
                student_user["id"],
                "Tu postulación cambió de estado",
                f"La postulación #{application_id} ahora está marcada como: {status}.",
            )
    return jsonify({"id": application_id, "status": status})


@app.get("/api/notifications")
@login_required
def notifications():
    with get_db() as connection:
        rows = connection.execute(
            """SELECT * FROM notifications WHERE user_id = ?
               ORDER BY created_at DESC LIMIT 30""",
            (session["user_id"],),
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/suggestions")
@login_required
def create_suggestion():
    data = request.get_json(silent=True) or request.form
    category = str(data.get("category", "")).strip()
    subject = str(data.get("subject", "")).strip()
    message = str(data.get("message", "")).strip()
    allowed_categories = {"mejora", "problema", "vacante", "otro"}
    if category not in allowed_categories or not subject or not message:
        return jsonify({"error": "Selecciona un tema y completa el título y la sugerencia."}), 400
    if len(subject) > 120 or len(message) < 15 or len(message) > 2000:
        return jsonify({"error": "El título debe tener hasta 120 caracteres y el mensaje entre 15 y 2,000."}), 400
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "student":
            return jsonify({"error": "El buzón está disponible para cuentas de estudiantes."}), 403
        recent = connection.execute(
            """SELECT created_at FROM suggestions WHERE user_id = ?
               ORDER BY id DESC LIMIT 1""",
            (user["id"],),
        ).fetchone()
        if recent:
            created = datetime.strptime(recent["created_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - created < timedelta(minutes=1):
                return jsonify({"error": "Espera un minuto antes de enviar otra sugerencia."}), 429
        suggestion_id = connection.execute(
            """INSERT INTO suggestions (user_id, category, subject, message)
               VALUES (?, ?, ?, ?)""",
            (user["id"], category, subject, message),
        ).lastrowid
    return jsonify({"id": suggestion_id, "message": "Gracias. Tu sugerencia fue enviada a la universidad."}), 201


@app.get("/api/suggestions")
@login_required
def list_suggestions():
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "Solo el personal autorizado puede revisar sugerencias."}), 403
        rows = connection.execute(
            """SELECT suggestions.*, users.name AS student_name, users.email AS student_email
               FROM suggestions JOIN users ON users.id = suggestions.user_id
               ORDER BY suggestions.created_at DESC LIMIT 200"""
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/suggestions/<int:suggestion_id>")
@login_required
def update_suggestion(suggestion_id):
    data = request.get_json(silent=True) or request.form
    status = str(data.get("status", "")).strip()
    if status not in {"new", "reviewing", "resolved"}:
        return jsonify({"error": "Estado de sugerencia no válido."}), 400
    with get_db() as connection:
        user = session_user(connection)
        if not user or user["role"] != "teacher":
            return jsonify({"error": "No tienes permisos para actualizar sugerencias."}), 403
        cursor = connection.execute(
            "UPDATE suggestions SET status = ? WHERE id = ?",
            (status, suggestion_id),
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "La sugerencia no existe."}), 404
    return jsonify({"id": suggestion_id, "status": status})


@app.patch("/api/notifications/<int:notification_id>/read")
@login_required
def mark_notification_read(notification_id):
    with get_db() as connection:
        cursor = connection.execute(
            "UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
            (notification_id, session["user_id"]),
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "La notificación no existe."}), 404
    return jsonify({"id": notification_id, "read": True})


@app.get("/api/students")
@login_required
def students():
    with get_db() as connection:
        current = connection.execute(
            "SELECT id, role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if current["role"] != "teacher":
            return jsonify({"error": "Solo personal autorizado de la universidad puede consultar perfiles."}), 403
        career = request.args.get("career", "").strip()
        interest = request.args.get("interest", "").strip()
        query = """
            SELECT students.id, students.name, students.email, students.career,
                   students.interest, students.skills, students.cv_filename,
                   students.created_at, students.privacy_consent,
                   students.approval_status, students.approval_note, users.id AS user_id
            FROM students LEFT JOIN users ON users.email = students.email
            WHERE (? = '' OR students.career = ?)
              AND (? = '' OR students.interest = ?)
        """
        params = [career, career, interest, interest]
        query += " ORDER BY students.created_at DESC"
        rows = connection.execute(
            query, params
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/students/export")
@login_required
def export_students():
    with get_db() as connection:
        current = session_user(connection)
        if current["role"] != "teacher":
            return jsonify({"error": "Solo un maestro puede exportar el directorio."}), 403
        rows = connection.execute(
            "SELECT name, email, career, interest, skills, approval_status, created_at FROM students ORDER BY name"
        ).fetchall()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Nombre", "Correo", "Carrera", "Interés", "Habilidades", "Estado", "Registro"])
    writer.writerows([tuple(row) for row in rows])
    response = app.response_class(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=upowork-alumnos.csv"
    return response


@app.patch("/api/students/<int:student_id>/approval")
@login_required
def approve_student(student_id):
    data = request.get_json(silent=True) or request.form
    status = str(data.get("status", "")).strip()
    if status not in {"pending", "approved", "rejected"}:
        return jsonify({"error": "Estado de perfil no válido."}), 400
    with get_db() as connection:
        teacher = connection.execute("SELECT role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not teacher or teacher["role"] != "teacher":
            return jsonify({"error": "Solo un maestro puede aprobar perfiles."}), 403
        student = connection.execute("SELECT id FROM students WHERE id = ?", (student_id,)).fetchone()
        if not student:
            return jsonify({"error": "El perfil no existe."}), 404
        connection.execute("UPDATE students SET approval_status = ?, approval_note = ? WHERE id = ?", (status, str(data.get("note", "")).strip(), student_id))
    return jsonify({"id": student_id, "approval_status": status})


@app.delete("/api/students/<int:student_id>")
@login_required
def delete_student(student_id):
    with get_db() as connection:
        current = session_user(connection)
        if not current or current["role"] != "teacher":
            return jsonify({"error": "Solo un maestro puede administrar cuentas."}), 403
        student = connection.execute(
            "SELECT email, cv_filename FROM students WHERE id = ?", (student_id,)
        ).fetchone()
        if not student:
            return jsonify({"error": "El perfil no existe."}), 404
        connection.execute("DELETE FROM students WHERE id = ?", (student_id,))
        connection.execute(
            "DELETE FROM users WHERE email = ? AND role = 'student'", (student["email"],)
        )
    if student["cv_filename"]:
        cv_path = UPLOADS / student["cv_filename"]
        if cv_path.exists():
            cv_path.unlink()
    return jsonify({"message": "Perfil y cuenta eliminados."})


@app.get("/api/students/<int:student_id>/cv")
@login_required
def student_cv(student_id):
    with get_db() as connection:
        current = connection.execute(
            "SELECT id, role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        student = connection.execute(
            "SELECT cv_filename FROM students WHERE id = ?", (student_id,)
        ).fetchone()
    if not current or current["role"] != "teacher":
        return jsonify({"error": "Solo personal autorizado de la universidad puede consultar CVs."}), 403
    if not student or not student["cv_filename"]:
        return jsonify({"error": "Este alumno no tiene un CV adjunto."}), 404
    return send_from_directory(UPLOADS, student["cv_filename"], as_attachment=True)


@app.get("/api/profile")
@login_required
def own_profile():
    with get_db() as connection:
        user = connection.execute(
            "SELECT email FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        profile = connection.execute(
            "SELECT * FROM students WHERE email = ?", (user["email"],)
        ).fetchone()
    return jsonify(dict(profile) if profile else None)


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
        return jsonify({"error": "Ingresa un correo válido, por ejemplo nombre@gmail.com."}), 400

    cv = request.files.get("cv")
    cv_filename = None
    if cv and cv.filename:
        if not valid_pdf(cv):
            return jsonify({"error": "El CV debe estar en formato PDF."}), 400
        cv_filename = f"{uuid.uuid4().hex}_{secure_filename(cv.filename)}"
        cv.save(UPLOADS / cv_filename)

    values = (
        request.form["name"].strip(),
        email,
        request.form["career"].strip(),
        request.form["interest"].strip(),
        request.form["skills"].strip(),
        request.form["password"].strip(),
    )
    if len(values[-1]) < 12:
        return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
    try:
        with get_db() as connection:
            connection.execute("BEGIN")
            existing_user = connection.execute(
                "SELECT id, role FROM users WHERE email = ?", (values[1].lower(),)
            ).fetchone()
            if existing_user and existing_user["role"] != "student":
                return jsonify({"error": "Ese correo ya pertenece a otra cuenta."}), 409
            if existing_user:
                connection.execute(
                    "UPDATE users SET name = ?, password_hash = ? WHERE id = ?",
                    (values[0], generate_password_hash(values[-1]), existing_user["id"]),
                )
            else:
                connection.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                    (values[0], values[1].lower(), generate_password_hash(values[-1])),
                )
            existing_profile = connection.execute(
                "SELECT id, cv_filename FROM students WHERE email = ?", (values[1],)
            ).fetchone()
            if existing_profile:
                connection.execute(
                    """UPDATE students SET name = ?, career = ?, interest = ?, skills = ?,
                       cv_filename = COALESCE(?, cv_filename), privacy_consent = 1,
                       approval_status = 'pending' WHERE id = ?""",
                    (*values[0:1], values[2], values[3], values[4], cv_filename, existing_profile["id"]),
                )
                profile_id = existing_profile["id"]
            else:
                profile_id = connection.execute(
                    """
                    INSERT INTO students (name, email, career, interest, skills, cv_filename, privacy_consent)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*values[:-1], cv_filename, 1),
                ).lastrowid
            student_user = connection.execute(
                "SELECT id FROM users WHERE email = ?", (values[1],)
            ).fetchone()
            csrf = secrets.token_urlsafe(32)
            session.clear()
            session["user_id"] = student_user["id"]
            session["csrf_token"] = csrf
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ya existe un perfil registrado con ese correo."}), 409

    return jsonify({"id": profile_id, "message": "Perfil guardado correctamente."}), 201


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({"error": "El CV no puede superar los 5 MB."}), 413


initialize_database()

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
        "form-action 'self' mailto:; base-uri 'self'; frame-ancestors 'none'",
    )
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=app_environment != "production" and os.environ.get("UPOWORK_DEBUG", "").lower() == "true",
    )
