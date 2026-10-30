from pathlib import Path
import sqlite3
import os
import re
import uuid
import secrets
from functools import wraps
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory, session, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "upotec.db"
UPLOADS = BASE_DIR / "uploads"
UPLOADS.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


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
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                worked TEXT NOT NULL,
                comment TEXT NOT NULL,
                show_name INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/perfil")
def perfil():
    return render_template("registro-personal.html")


@app.get("/opiniones")
def opiniones():
    return render_template("opiniones.html")


@app.get("/aviso-privacidad")
def aviso_privacidad():
    return render_template("aviso-privacidad.html")


@app.get("/terminos-de-uso")
def terminos_de_uso():
    return render_template("terminos-de-uso.html")


@app.get("/preguntas-frecuentes")
def preguntas_frecuentes():
    return render_template("preguntas-frecuentes.html")


@app.get("/contacto")
def contacto():
    return render_template("contacto.html")


@app.get("/sugerencias")
def sugerencias():
    return render_template("sugerencias.html")


@app.get("/consejos")
def consejos():
    return render_template("consejos.html")


@app.get("/empresas")
def empresas():
    return render_template("empresas.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/api/csrf-token")
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]})


@app.post("/api/login")
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401
    
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"name": user["name"], "role": user["role"]})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada correctamente"})


@app.post("/api/registro")
def registro():
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
        cv_filename = f"{uuid.uuid4().hex}_{secure_filename(cv_file.filename)}"
        cv_file.save(UPLOADS / cv_filename)
    
    password_hash = generate_password_hash(contrasena)
    
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (name, email, password_hash, role)
                VALUES (?, ?, ?, 'student')
            """, (nombre, email, password_hash))
            
            conn.execute("""
                INSERT INTO students (name, email, career, interest, skills, cv_filename, privacy_consent)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (nombre, email, carrera, intereses, habilidades, cv_filename))
    except sqlite3.IntegrityError:
        return jsonify({"error": "Este correo ya está registrado"}), 400
    
    return jsonify({"mensaje": "Registro exitoso"})


@app.post("/api/feedback")
@login_required
def guardar_feedback():
    user_id = session["user_id"]
    calificacion = request.form.get("calificacion", type=int)
    funcionamiento = request.form.get("funcionamiento", "").strip()
    comentario = request.form.get("comentario", "").strip()
    mostrar_nombre = 1 if request.form.get("mostrar_nombre") == "on" else 0
    
    if not calificacion or not (1 <= calificacion <= 5):
        return jsonify({"error": "Calificación inválida"}), 400
    if not funcionamiento:
        return jsonify({"error": "Selecciona una opción sobre el funcionamiento"}), 400
    if not comentario:
        return jsonify({"error": "Escribe un comentario"}), 400
    
    ahora = datetime.now().isoformat()
    
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO feedback (user_id, rating, worked, comment, show_name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, calificacion, funcionamiento, comentario, mostrar_nombre, ahora, ahora))
    except sqlite3.IntegrityError:
        with get_db() as conn:
            conn.execute("""
                UPDATE feedback
                SET rating = ?, worked = ?, comment = ?, show_name = ?, updated_at = ?
                WHERE user_id = ?
            """, (calificacion, funcionamiento, comentario, mostrar_nombre, ahora, user_id))
    
    return jsonify({"mensaje": "Gracias por tu opinión"})


@app.get("/api/opiniones-publicas")
def opiniones_publicas():
    with get_db() as conn:
        opiniones = conn.execute("""
            SELECT f.rating, f.comment, f.created_at,
                   CASE WHEN f.show_name = 1 THEN u.name ELSE 'Anónimo' END AS autor
            FROM feedback f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.created_at DESC
        """).fetchall()
    
    return jsonify([dict(op) for op in opiniones])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
