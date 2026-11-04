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

from flask import Flask, jsonify, request, send_from_directory, session, render_template, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", str(BASE_DIR / "uploads")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("UPOWORK_SECRET", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id TEXT PRIMARY KEY,
            correo TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            contrasena TEXT NOT NULL,
            rol TEXT DEFAULT 'usuario',
            creado TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            pass

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals.update(csrf_token=generate_csrf_token)

# ========== RUTAS DE PÁGINAS ==========

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vacantes")
def vacantes():
    return render_template("vacantes.html")

@app.route("/consejos")
def consejos():
    return render_template("consejos.html")

@app.route("/empresas")
def empresas():
    return render_template("empresas.html")

@app.route("/opiniones")
def opiniones():
    return render_template("opiniones.html")

@app.route("/registro-personal", methods=["GET", "POST"])
def registro_personal():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        codigo = request.form.get("codigo", "").strip()
        contrasena = request.form.get("contrasena", "")

        CODIGO_AUTORIZADO = "UPOTEC-2026"

        if codigo != CODIGO_AUTORIZADO:
            return render_template("registro-personal.html", error="Código de invitación incorrecto")

        if not all([nombre, correo, contrasena]):
            return render_template("registro-personal.html", error="Completa todos los campos")

        hashed = generate_password_hash(contrasena)
        user_id = str(uuid.uuid4())

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO usuarios (id, correo, nombre, contrasena, rol) VALUES (?, ?, ?, ?, ?)",
                (user_id, correo, nombre, hashed, "personal")
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("registro-personal.html", error="El correo ya está registrado")

    return render_template("registro-personal.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        correo = request.form.get("correo", "").strip()
        contrasena = request.form.get("contrasena", "")

        conn = get_db()
        usuario = conn.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,)).fetchone()
        conn.close()

        if usuario and check_password_hash(usuario["contrasena"], contrasena):
            session["usuario_id"] = usuario["id"]
            session["nombre"] = usuario["nombre"]
            session["rol"] = usuario["rol"]
            session.permanent = True
            return redirect(url_for("index"))
        else:
            error = "Correo o contraseña incorrectos"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ========== FIN DE RUTAS ==========

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
