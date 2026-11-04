from pathlib import Path
import os
import secrets
import sqlite3
import uuid
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session
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
    connection = sqlite3.connect(DATABASE, timeout=20)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
            );
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
            CREATE TABLE IF NOT EXISTS opinions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)


init_db()


def csrf_valid():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Inicia sesión primero"}), 401
        return view(*args, **kwargs)
    return wrapped


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
        app.logger.exception("Database health check failed")
        return jsonify({"status": "error", "database": "unavailable"}), 503


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.post("/login")
def login_post():
    user = authenticate(request.form.get("email", ""), request.form.get("password", ""), request.form.get("role") or None)
    if not user:
        return render_template("login.html", error="Correo, contraseña o tipo de cuenta incorrectos."), 401
    return redirect("/dashboard")


@app.post("/api/login")
def api_login():
    if not csrf_valid():
        return jsonify({"error": "La sesión expiró. Recarga la página e inténtalo otra vez."}), 400
    data = request.form if request.form else (request.get_json(silent=True) or {})
    user = authenticate(str(data.get("email", "")), str(data.get("password", "")), data.get("role"))
    if not user:
        return jsonify({"error": "Correo, contraseña o tipo de cuenta incorrectos."}), 401
    return jsonify({"message": "Sesión iniciada", "user": {"name": user["name"], "role": user["role"]}})


@app.get("/dashboard")
@app.get("/dashboard.html")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


@app.post("/api/logout")
def logout():
    if "user_id" not in session:
        return jsonify({"error": "Inicia sesión primero"}), 401
    if not csrf_valid():
        return jsonify({"error": "La sesión expiró. Recarga la página."}), 400
    session.clear()
    return jsonify({"message": "Sesión cerrada"})


@app.get("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"error": "No autenticado"}), 401
    with get_db() as conn:
        user = conn.execute("SELECT id,name,email,role FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user:
        session.clear()
        return jsonify({"error": "No autenticado"}), 401
    return jsonify(dict(user))


@app.get("/registrar")
@app.get("/perfil")
@app.get("/perfil.html")
def perfil():
    # The student form is public: a student has to be able to create an account first.
    return render_template("perfil.html")


@app.post("/api/profiles")
@app.post("/api/registro")
def register_profile():
    if not csrf_valid():
        return jsonify({"error": "La sesión expiró. Recarga la página e inténtalo otra vez."}), 400
    name = (request.form.get("name") or request.form.get("nombre") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    career = (request.form.get("career") or request.form.get("carrera") or "").strip()
    interest = (request.form.get("interest") or request.form.get("intereses") or "").strip()
    skills = (request.form.get("skills") or request.form.get("habilidades") or "").strip()
    password = request.form.get("password") or request.form.get("contrasena") or ""
    consent = request.form.get("privacy_consent") in ("1", "on", "true") or request.form.get("acepta_privacidad") in ("1", "on", "true")
    if not all((name, email, career, interest, skills, password)):
        return jsonify({"error": "Todos los campos son obligatorios."}), 400
    if len(password) < 12:
        return jsonify({"error": "La contraseña debe tener al menos 12 caracteres."}), 400
    if not consent:
        return jsonify({"error": "Debes aceptar el aviso de privacidad."}), 400

    cv = request.files.get("cv")
    cv_filename = None
    if cv and cv.filename:
        if not secure_filename(cv.filename).lower().endswith(".pdf"):
            return jsonify({"error": "El CV debe ser un PDF."}), 400
        if cv.stream.read(5) != b"%PDF-":
            return jsonify({"error": "El archivo no parece ser un PDF válido."}), 400
        cv.stream.seek(0)
        cv_filename = f"{uuid.uuid4().hex}.pdf"
        cv.save(UPLOADS / cv_filename)
    try:
        with get_db() as conn:
            cursor = conn.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'student')", (name, email, generate_password_hash(password)))
            conn.execute("INSERT INTO students (name,email,career,interest,skills,cv_filename,privacy_consent) VALUES (?,?,?,?,?,?,1)", (name, email, career, interest, skills, cv_filename))
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        if cv_filename:
            (UPLOADS / cv_filename).unlink(missing_ok=True)
        return jsonify({"error": "Este correo ya está registrado."}), 400
    session.clear()
    session.update(user_id=user_id, name=name, role="student")
    return jsonify({"message": "Registro exitoso"}), 201


@app.get("/api/profile")
@api_login_required
def student_profile():
    with get_db() as conn:
        user = conn.execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
        profile = conn.execute("SELECT * FROM students WHERE lower(email)=lower(?)", (user["email"],)).fetchone() if user else None
    return jsonify(dict(profile) if profile else None)


@app.get("/opiniones")
def opiniones():
    return render_template("opiniones.html")


@app.get("/api/opinions")
def list_opinions():
    with get_db() as conn:
        rows = conn.execute("SELECT id,comment,created_at FROM opinions ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/opinions")
def create_opinion():
    if not csrf_valid():
        return jsonify({"error": "La sesión expiró. Recarga la página e inténtalo otra vez."}), 400
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


@app.post("/opiniones")
def opiniones_guardar():
    # Backwards compatibility for older no-JS form submissions.
    if not csrf_valid():
        return "La sesión expiró. Recarga la página e inténtalo otra vez.", 400
    comment = request.form.get("comentario", "").strip()
    if not 10 <= len(comment) <= 1200:
        return "La opinión debe tener entre 10 y 1,200 caracteres.", 400
    with get_db() as conn:
        conn.execute("INSERT INTO opinions (comment) VALUES (?)", (comment,))
    return redirect("/opiniones?enviada=1", code=303)


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.get("/registro-personal")
def registro_personal_page():
    return render_template("registro-personal.html")


@app.post("/registro-personal")
def registro_personal_post():
    name = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    code = request.form.get("codigo", "")
    password = request.form.get("password", "")
    invite_code = os.environ.get("UPOWORK_STAFF_INVITE_CODE", "")
    if not invite_code or not secrets.compare_digest(code, invite_code):
        return render_template("registro-personal.html", error="El código de invitación no es válido o no está configurado."), 400
    if not name or not email or len(password) < 12:
        return render_template("registro-personal.html", error="Completa los campos; la contraseña requiere 12 caracteres."), 400
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'teacher')", (name, email, generate_password_hash(password)))
    except sqlite3.IntegrityError:
        return render_template("registro-personal.html", error="Este correo ya está registrado."), 400
    return redirect("/login")


@app.get("/consejos")
def consejos():
    return render_template("consejos.html")


@app.get("/empresas")
def empresas():
    return render_template("empresas.html")


@app.get("/vacantes")
def vacantes():
    # The existing vacancies interface lives in empresas.html; do not render a missing template.
    return redirect("/empresas", code=302)


@app.get("/aviso-privacidad")
def aviso_privacidad():
    return render_template("aviso-privacidad.html")


@app.get("/terminos-de-uso")
def terminos():
    return render_template("terminos-de-uso.html")


@app.get("/preguntas-frecuentes")
def preguntas():
    return render_template("preguntas-frecuentes.html")


@app.get("/contacto")
def contacto():
    return render_template("contacto.html")


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
