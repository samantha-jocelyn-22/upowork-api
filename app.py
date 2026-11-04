from pathlib import Path
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.environ.get("UPOWORK_SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("UPOWORK_HTTPS", "false").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_admin_user():
    email = (os.environ.get("UPOWORK_ADMIN_EMAIL") or "admin@upotec.edu.mx").strip().lower()
    name = os.environ.get("UPOWORK_ADMIN_NAME") or "Coordinación UPOwork"
    password = os.environ.get("UPOWORK_ADMIN_PASSWORD") or "UPOAdmin2026!"
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                (name, email, generate_password_hash(password)),
            )


def init_db():
    with get_db() as conn:
        conn.executescript(
            """
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
                requirements TEXT,
                source_url TEXT NOT NULL,
                opportunity_type TEXT DEFAULT 'empleo',
                career TEXT,
                location TEXT,
                mode TEXT DEFAULT 'presencial',
                deadline TEXT,
                schedule TEXT,
                support TEXT,
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
            """
        )
    ensure_admin_user()


init_db()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Inicia sesión primero"}), 401
        return f(*args, **kwargs)

    return decorated_function


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# ---------- PÁGINAS ----------
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    if "user_id" in session:
        return redirect("/dashboard")
    return render_template("login.html")


@app.get("/dashboard")
def dashboard_page():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


@app.get("/dashboard.html")
def dashboard_page_html():
    return dashboard_page()


@app.get("/perfil")
def perfil_page():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("perfil.html", nombre=session.get("name"), rol=session.get("role"))


@app.get("/perfil.html")
def perfil_html():
    return perfil_page()


@app.get("/registrar")
def registrar_redirect():
    return redirect("/perfil")


@app.get("/registro-personal")
def registro_personal_page():
    return render_template("registro-personal.html")


@app.get("/registro-personal.html")
def registro_personal_html():
    return registro_personal_page()


@app.get("/empresas")
def empresas():
    return render_template("empresas.html")


@app.get("/empresas.html")
def empresas_html():
    return empresas()


@app.get("/consejos")
def consejos():
    return render_template("consejos.html")


@app.get("/consejos.html")
def consejos_html():
    return consejos()


@app.get("/vacantes")
def vacantes():
    return render_template("vacantes.html")


@app.get("/vacantes.html")
def vacantes_html():
    return vacantes()


@app.get("/opiniones")
def opiniones():
    return render_template("opiniones.html")


@app.get("/opiniones.html")
def opiniones_html():
    return opiniones()


@app.get("/sugerencias")
def sugerencias():
    return render_template("sugerencias.html")


@app.get("/sugerencias.html")
def sugerencias_html():
    return sugerencias()


@app.get("/aviso-privacidad")
def aviso_privacidad():
    return render_template("aviso-privacidad.html")


@app.get("/terminos-de-uso")
def terminos_uso():
    return render_template("terminos-de-uso.html")


@app.get("/preguntas-frecuentes")
def preguntas_frecuentes():
    return render_template("preguntas-frecuentes.html")


@app.get("/contacto")
def contacto():
    return render_template("contacto.html")


@app.get("/empresa-registro")
def empresa_registro():
    return render_template("empresa-registro.html")


# ---------- AUTENTICACIÓN ----------
@app.post("/login")
def login_post():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("login.html", error="Correo y contraseña obligatorios")

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Correo o contraseña incorrectos")

    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    return redirect("/dashboard")


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.post("/api/login")
def api_login():
    data = request.form if request.form else request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({"error": "Correo y contraseña obligatorios"}), 400

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Correo o contraseña incorrectos"}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    return jsonify({"message": "Sesión iniciada", "user": {"id": user["id"], "name": user["name"], "role": user["role"]}})


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada"})


# ---------- REGISTRO ----------
@app.post("/api/profiles")
@app.post("/api/registro")
def register_profile():
    nombre = (request.form.get("name") or request.form.get("nombre") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    carrera = (request.form.get("career") or "").strip()
    intereses = (request.form.get("interest") or request.form.get("intereses") or "").strip()
    habilidades = (request.form.get("skills") or request.form.get("habilidades") or "").strip()
    password = request.form.get("password") or request.form.get("contrasena") or ""
    acepta = request.form.get("privacy_consent") in ("1", "on", "true") or request.form.get("acepta_privacidad") in ("1", "on", "true")

    if not all([nombre, email, carrera, intereses, habilidades, password]):
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    if not acepta:
        return jsonify({"error": "Debes aceptar el aviso de privacidad"}), 400
    if len(password) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres"}), 400

    cv_file = request.files.get("cv")
    cv_filename = None
    if cv_file and cv_file.filename:
        if not cv_file.filename.lower().endswith(".pdf"):
            return jsonify({"error": "El CV debe estar en formato PDF"}), 400
        cv_filename = f"{uuid.uuid4().hex}_{cv_file.filename}"
        cv_file.save(UPLOADS / cv_filename)

    password_hash = generate_password_hash(password)
    with get_db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                (nombre, email, password_hash),
            )
            user_id = cur.lastrowid
            conn.execute(
                "INSERT INTO students (user_id, name, email, career, interest, skills, cv_filename, privacy_consent) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (user_id, nombre, email, carrera, intereses, habilidades, cv_filename),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Este correo ya está registrado"}), 400

    session.clear()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    return jsonify({"message": "Registro exitoso"})


@app.post("/registro-personal")
def registro_personal_post():
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    codigo = request.form.get("codigo", "").strip()
    password = request.form.get("password", "")
    autorizado = "UPOADMIN2026"

    if codigo != autorizado:
        return render_template("registro-personal.html", error="Código de invitación incorrecto")
    if not nombre or not email or len(password) < 8:
        return render_template("registro-personal.html", error="Completa todos los campos (contraseña mínima 8 caracteres)")

    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'teacher')",
                (nombre, email, generate_password_hash(password)),
            )
        except sqlite3.IntegrityError:
            return render_template("registro-personal.html", error="Este correo ya está registrado")

    return redirect("/login")


# ---------- APIs DE APLICACIÓN ----------
@app.get("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    user = current_user()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 401
    return jsonify({"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]})


@app.get("/api/profile")
def api_student_profile():
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    with get_db() as conn:
        profile = conn.execute(
            "SELECT * FROM students WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (session["user_id"],),
        ).fetchone()
    return jsonify(dict(profile) if profile else None)


@app.get("/api/applications")
def api_applications():
    if "user_id" not in session:
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT a.*, v.company_name, v.title, v.source_url, v.status AS vacancy_status
            FROM applications a
            JOIN vacancies v ON v.id = a.vacancy_id
            WHERE a.user_id = ?
            ORDER BY a.created_at DESC
            """,
            (session["user_id"],),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/notifications")
def api_notifications():
    if "user_id" not in session:
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (session["user_id"],),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/recommendations")
def api_recommendations():
    if "user_id" not in session:
        return jsonify([])
    with get_db() as conn:
        student = conn.execute("SELECT * FROM students WHERE user_id = ? ORDER BY id DESC LIMIT 1", (session["user_id"],)).fetchone()
        if not student:
            return jsonify([])
        vacancies = conn.execute(
            "SELECT * FROM vacancies WHERE status = 'active' ORDER BY created_at DESC LIMIT 10"
        ).fetchall()
    query = f"{student['career']} {student['interest']} {student['skills']}".lower()
    items = []
    for vacancy in vacancies:
        text = f"{vacancy['title']} {vacancy['company_name']} {vacancy['description']} {vacancy['requirements']} {vacancy['career']}".lower()
        match = 1 if query and text and any(word in text for word in query.split()) else 0
        if not match and vacancy["career"] in ("", student["career"]):
            match = 1
        if match:
            items.append({
                "id": vacancy["id"],
                "title": vacancy["title"],
                "company_name": vacancy["company_name"],
                "location": vacancy["location"],
                "mode": vacancy["mode"],
                "career": vacancy["career"],
                "source_url": vacancy["source_url"],
                "match_reasons": ["Coincide con tu carrera", "Se ajusta a tus intereses"],
            })
    return jsonify(items[:5])


@app.get("/api/vacancies")
def api_vacancies():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM vacancies WHERE status = 'active' ORDER BY created_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/vacancies")
def post_vacancy():
    if "user_id" not in session:
        return jsonify({"error": "Inicia sesión primero"}), 401
    user = current_user()
    if user["role"] not in ("teacher", "admin"):
        return jsonify({"error": "No autorizado"}), 403

    payload = request.get_json(silent=True) or {}
    company_name = (payload.get("company_name") or "").strip()
    title = (payload.get("title") or "").strip()
    source_url = (payload.get("source_url") or "").strip()
    description = (payload.get("description") or "").strip()
    requirements = (payload.get("requirements") or "").strip()
    career = (payload.get("career") or "").strip()
    if not all([company_name, title, source_url, description]):
        return jsonify({"error": "Empresa, título, enlace y descripción son obligatorios"}), 400

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO vacancies (
                company_name, title, description, requirements, source_url, opportunity_type,
                career, location, mode, deadline, schedule, support, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                company_name,
                title,
                description,
                requirements,
                source_url,
                payload.get("opportunity_type") or "empleo",
                career,
                payload.get("location") or "",
                payload.get("mode") or "presencial",
                payload.get("deadline") or "",
                payload.get("schedule") or "",
                payload.get("support") or "",
                session["user_id"],
            ),
        )
    return jsonify({"message": "Oportunidad publicada"})


@app.patch("/api/vacancies/<int:vacancy_id>")
def close_vacancy(vacancy_id):
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    user = current_user()
    if user["role"] not in ("teacher", "admin"):
        return jsonify({"error": "No autorizado"}), 403

    payload = request.get_json(silent=True) or {}
    status = payload.get("status") or "closed"
    with get_db() as conn:
        conn.execute("UPDATE vacancies SET status = ? WHERE id = ?", (status, vacancy_id))
    return jsonify({"message": "Vacante actualizada"})


@app.post("/api/vacancies/<int:vacancy_id>/applications")
def apply_vacancy(vacancy_id):
    if "user_id" not in session:
        return jsonify({"error": "Inicia sesión como alumno para postularte."}), 401
    user = current_user()
    if user["role"] != "student":
        return jsonify({"error": "La postulación es para alumnos."}), 403

    with get_db() as conn:
        vacancy = conn.execute("SELECT * FROM vacancies WHERE id = ?", (vacancy_id,)).fetchone()
        if not vacancy:
            return jsonify({"error": "Vacante no encontrada"}), 404
        try:
            conn.execute(
                "INSERT INTO applications (user_id, vacancy_id, status) VALUES (?, ?, 'pending')",
                (session["user_id"], vacancy_id),
            )
        except sqlite3.IntegrityError:
            return jsonify({"message": "Ya te habías postulado antes."})
    return jsonify({"message": "Postulación enviada"})


@app.get("/api/students")
def api_students():
    if "user_id" not in session:
        return jsonify([])
    user = current_user()
    if user["role"] not in ("teacher", "admin"):
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute(
            "SELECT s.*, u.email FROM students s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/api/students/<int:student_id>/approval")
def api_approve_student(student_id):
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    user = current_user()
    if user["role"] not in ("teacher", "admin"):
        return jsonify({"error": "No autorizado"}), 403
    payload = request.get_json(silent=True) or {}
    status = payload.get("status") or "approved"
    with get_db() as conn:
        conn.execute("UPDATE students SET approval_status = ? WHERE id = ?", (status, student_id))
    return jsonify({"message": "Estado actualizado"})


@app.get("/api/suggestions")
def api_suggestions():
    if "user_id" not in session:
        return jsonify([])
    if current_user()["role"] not in ("teacher", "admin"):
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, u.name AS student_name
            FROM suggestions s
            JOIN users u ON u.id = s.user_id
            ORDER BY s.created_at DESC
            """
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.patch("/api/suggestions/<int:suggestion_id>")
def patch_suggestion(suggestion_id):
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    if current_user()["role"] not in ("teacher", "admin"):
        return jsonify({"error": "No autorizado"}), 403
    payload = request.get_json(silent=True) or {}
    status = payload.get("status") or "reviewed"
    with get_db() as conn:
        conn.execute("UPDATE suggestions SET status = ? WHERE id = ?", (status, suggestion_id))
    return jsonify({"message": "Sugerencia actualizada"})


@app.post("/api/suggestions")
def create_suggestion():
    if "user_id" not in session:
        return jsonify({"error": "Inicia sesión primero"}), 401
    payload = request.get_json(silent=True) or {}
    category = (payload.get("category") or "").strip()
    subject = (payload.get("subject") or "").strip()
    message = (payload.get("message") or "").strip()
    if not all([category, subject, message]):
        return jsonify({"error": "Completa tema, título y mensaje"}), 400
    with get_db() as conn:
        conn.execute(
            "INSERT INTO suggestions (user_id, category, subject, message) VALUES (?, ?, ?, ?)",
            (session["user_id"], category, subject, message),
        )
    return jsonify({"message": "Sugerencia enviada"})


@app.get("/api/students/export")
def export_students():
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    if current_user()["role"] not in ("teacher", "admin"):
        return jsonify({"error": "No autorizado"}), 403

    with get_db() as conn:
        rows = conn.execute(
            "SELECT name, email, career, interest, skills, approval_status FROM students ORDER BY created_at DESC"
        ).fetchall()
    csv_lines = ["name,email,career,interest,skills,approval_status"]
    for row in rows:
        csv_lines.append(
            ','.join([
                str(row["name"] or "").replace(',', ';'),
                str(row["email"] or "").replace(',', ';'),
                str(row["career"] or "").replace(',', ';'),
                str(row["interest"] or "").replace(',', ';'),
                str(row["skills"] or "").replace(',', ';'),
                str(row["approval_status"] or "").replace(',', ';'),
            ])
        )
    from flask import Response
    return Response("\n".join(csv_lines), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alumnos-upowork.csv"})


# ---------- RUTA DE FALLBACK PARA ARCHIVOS ESTÁTICOS SIN PREFIX ----------
@app.route('/styles.css')
def root_styles():
    return send_from_directory('static', 'styles.css')


@app.route('/script.js')
def root_script():
    return send_from_directory('static', 'script.js')


@app.route('/dashboard.js')
def root_dashboard_js():
    return send_from_directory('static', 'dashboard.js')


@app.route('/upowork-logo.svg')
def root_logo():
    return send_from_directory('static', 'upowork-logo.svg')


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
