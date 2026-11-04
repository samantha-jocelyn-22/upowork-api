import os
import secrets

from flask import redirect, render_template, request
from werkzeug.security import generate_password_hash

from app import app, get_db


@app.post("/registro-personal")
def registro_personal_post():
    name = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    code = request.form.get("codigo", "")
    password = request.form.get("password", "")
    invite_code = os.environ.get("UPOWORK_STAFF_INVITE_CODE", "")

    if not name or not email or not password or not code:
        return render_template("registro-personal.html", error="Completa todos los campos."), 400
    if len(password) < 12:
        return render_template("registro-personal.html", error="La contraseña debe tener al menos 12 caracteres."), 400
    if not invite_code:
        app.logger.error("UPOWORK_STAFF_INVITE_CODE is not configured")
        return render_template("registro-personal.html", error="El registro de personal no está habilitado. Contacta a la administración."), 503
    if not secrets.compare_digest(code, invite_code):
        return render_template("registro-personal.html", error="El código de invitación no es válido."), 400

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'teacher')",
                (name, email, generate_password_hash(password)),
            )
    except Exception as error:
        # Avoid disclosing database internals; handle duplicate email distinctly.
        import sqlite3
        if isinstance(error, sqlite3.IntegrityError):
            return render_template("registro-personal.html", error="Este correo ya está registrado."), 409
        raise

    return redirect("/login", code=303)
