from pathlib import Path
import os
import sqlite3

DATABASE = Path(os.environ.get("UPOWORK_DATABASE", "upotec.db")).resolve()
UPLOADS = Path(os.environ.get("UPOWORK_UPLOADS", "uploads")).resolve()
MARKER = DATABASE.with_name(".upowork-demo-reset-complete")
CONFIRMATION = "BORRAR DATOS DE DEMO UPOWORK"


def main():
    # This deploy-time one-shot utility is inert unless an exact opt-in is set.
    if os.environ.get("UPOWORK_RESET_DEMO_DATA") != CONFIRMATION:
        print("Demo-data reset not requested; leaving database and uploads unchanged.")
        return

    # The marker is on the persistent data volume, so restarts won't repeat deletion.
    if MARKER.exists():
        print("Demo-data reset already completed; leaving data unchanged.")
        return

    if not DATABASE.exists():
        print(f"Database file not found at {DATABASE}; nothing to reset.")
        return

    tables_to_clear = (
        "notifications",
        "suggestions",
        "applications",
        "students",
        "vacancies",
        "opinions",
        "users",
    )
    with sqlite3.connect(DATABASE, timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        existing = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        # Avoid deleting any unrelated tables in a database that shares this file.
        for table in tables_to_clear:
            if table in existing:
                conn.execute(f'DELETE FROM "{table}"')
        conn.commit()

    # Uploaded CVs are personal data too. Remove files, not folders or the mount.
    if UPLOADS.exists():
        for path in UPLOADS.iterdir():
            if path.is_file() or path.is_symlink():
                path.unlink(missing_ok=True)

    MARKER.write_text("completed\n", encoding="utf-8")
    print("Demo data and uploaded files cleared once. The app will recreate its configured staff account on startup, if configured.")


if __name__ == "__main__":
    main()
