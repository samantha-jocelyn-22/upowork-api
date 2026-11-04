from pathlib import Path
import sqlite3
import os
import uuid
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request, session, render_template, send_from_directory, redirect

BASE_DIR = Path(__file__).resolve().parent

DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.environ.get("UPOWORK_SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("UPOWORK_HTTPS", "false").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ✅ Tu carpeta se llama "template" — así se lo decimos a Flask
app.template_folder = "templates"
app.static_folder = "static"


# ========== SERVIR ARCHIVOS ESTÁTICOS ==========
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


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
        """)


init_db()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Inicia sesión primero"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ========== PÁGINAS ==========
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.post("/login")
def login_post():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    
    from werkzeug.security import check_password_hash
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Correo o contraseña incorrectos")
    
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    return redirect("/")


@app.post("/api/logout")
def logout():
    session.clear()
    return redirect("/")


@app.get("/registro-personal")
def registro_personal():
    return render_template("registro-personal.html")


@app.post("/registro-personal")
def registro_personal_post():
    from werkzeug.security import generate_password_hash
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    codigo = request.form.get("codigo", "").strip()
    password = request.form.get("password", "")
    
    CODIGO_AUTORIZADO = "UPOADMIN2026"
    
    if codigo != CODIGO_AUTORIZADO:
        return render_template("registro-personal.html", error="Código de invitación incorrecto")
    
    if not nombre or not email or len(password) < 8:
        return render_template("registro-personal.html", error="Completa todos los campos (contraseña mínima 8 caracteres)")
    
    password_hash = generate_password_hash(password)
    
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (nombre, email, password_hash)
            )
    except sqlite3.IntegrityError:
        return render_template("registro-personal.html", error="Este correo ya está registrado")
    
    return redirect("/login")


@app.get("/opiniones")
def opiniones():
    return render_template("opiniones.html")


@app.post("/opiniones")
def opiniones_guardar():
    comentario = request.form.get("comentario", "").strip()
    if comentario:
        pass
    return redirect("/opiniones")


@app.get("/consejos")
def consejos():
    return render_template("consejos.html")


@app.get("/vacantes")
def vacantes():
    return render_template("vacantes.html")


@app.get("/empresas")
def empresas():
    return render_template("empresas.html")


@app.get("/perfil")
def perfil():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("perfil.html", nombre=session.get("name"), rol=session.get("role"))


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.post("/api/registro")
def registro():
    from werkzeug.security import generate_password_hash
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    carrera = request.form.get("carrera", "").strip()
    intereses = request.form.get("intereses", "").strip()
    habilidades = request.form.get("habilidades", "").strip()
    contrasena = request.form.get("contrasena", "")
    acepta_privacidad = request.form.get("acepta_privacidad") == "on"
    
    if not all([nombre, email, carrera, intereses, habilidades, contrasena]):
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    if not acepta_privacidad:
        return jsonify({"error": "Debes aceptar el aviso de privacidad"}), 400
    if len(contrasena) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres"}), 400
    
    cv_file = request.files.get("cv")
    cv_filename = None
    if cv_file and cv_file.filename:
        if not cv_file.filename.lower().endswith(".pdf"):
            return jsonify({"error": "El CV debe estar en formato PDF"}), 400
        cv_filename = f"{uuid.uuid4().hex}_{cv_file.filename}"
        cv_file.save(UPLOADS / cv_filename)
    
    password_hash = generate_password_hash(contrasena)
    
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                (nombre, email, password_hash)
            )
            conn.execute(
                "INSERT INTO students (name, email, career, interest, skills, cv_filename, privacy_consent) VALUES (?, ?, ?, ?, ?, ?, 1)",
                (nombre, email, carrera, intereses, habilidades, cv_filename)
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Este correo ya está registrado"}), 400
    
    return jsonify({"mensaje": "Registro exitoso"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
