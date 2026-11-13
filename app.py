from pathlib import Path
import os
import secrets
import sqlite3
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("UPOWORK_DATABASE", str(BASE_DIR / "upotec.db")))
DATABASE.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY=os.environ.get("UPOWORK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_SECURE=os.environ.get("UPOWORK_HTTPS", "false").lower() == "true",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=20)
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
            CREATE TABLE IF NOT EXISTS vacancies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()


init_db()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


# ===== RUTAS =====

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/dashboard")
def dashboard_page():
    return render_template("dashboard.html") if current_user() else redirect("/login")


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
                                   error="Este correo ya está registrado.",
                                   csrf_token=session["csrf_token"])
    
    return render_template("registro-personal.html", csrf_token=session["csrf_token"])


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
