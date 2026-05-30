"""
key_server.py
=============
Flask server that manages keys and HWID bindings.
Host this for free on Replit, Railway, or Render.

Install: python -m pip install flask

Set environment variables:
    BOT_SECRET=your_secret_here   (must match discord_bot.py)

Then run: python key_server.py
"""

from flask import Flask, request, jsonify
import sqlite3, secrets, string, os
from datetime import datetime

app       = Flask(__name__)
DB_FILE   = "keys.db"
BOT_SECRET = os.environ.get("BOT_SECRET", "changeme123")  # ← change this!

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key        TEXT PRIMARY KEY,
                hwid       TEXT    DEFAULT NULL,
                created_at TEXT    NOT NULL,
                bound_at   TEXT    DEFAULT NULL,
                note       TEXT    DEFAULT NULL,
                revoked    INTEGER DEFAULT 0
            )
        """)
    print(f"[DB] Ready — {DB_FILE}")

def make_key() -> str:
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "GTAG-" + "-".join(parts)

# ── Routes ────────────────────────────────────────────────────────────────────

def auth(data):
    return data.get("secret") == BOT_SECRET

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    key  = make_key()
    note = data.get("note", "")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO keys (key, created_at, note) VALUES (?, ?, ?)",
            (key, datetime.utcnow().isoformat(), note)
        )
    print(f"[KEY] Generated: {key}")
    return jsonify({"key": key})

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True) or {}
    key  = data.get("key",  "").strip().upper()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Missing key or HWID."})

    with get_db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()

        if not row:
            return jsonify({"valid": False, "message": "Key not found."})
        if row["revoked"]:
            return jsonify({"valid": False, "message": "Key has been revoked."})

        if row["hwid"] is None:
            # First use — bind HWID
            conn.execute(
                "UPDATE keys SET hwid = ?, bound_at = ? WHERE key = ?",
                (hwid, datetime.utcnow().isoformat(), key)
            )
            print(f"[KEY] Activated: {key} → {hwid[:12]}…")
            return jsonify({"valid": True, "message": "Key activated!"})

        if row["hwid"] == hwid:
            return jsonify({"valid": True, "message": "OK"})

        print(f"[KEY] HWID mismatch: {key}")
        return jsonify({"valid": False, "message": "Key is invalid."})

@app.route("/revoke", methods=["POST"])
def revoke():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    key = data.get("key", "").strip().upper()
    with get_db() as conn:
        conn.execute("UPDATE keys SET revoked = 1 WHERE key = ?", (key,))
    print(f"[KEY] Revoked: {key}")
    return jsonify({"ok": True})

@app.route("/reset", methods=["POST"])
def reset_hwid():
    """Unbind a key from its HWID (lets someone use it on a new PC)."""
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    key = data.get("key", "").strip().upper()
    with get_db() as conn:
        conn.execute("UPDATE keys SET hwid = NULL, bound_at = NULL WHERE key = ?", (key,))
    print(f"[KEY] HWID reset: {key}")
    return jsonify({"ok": True})

@app.route("/list", methods=["POST"])
def list_keys():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    with get_db() as conn:
        rows = conn.execute(
            "SELECT key, hwid, created_at, bound_at, note, revoked FROM keys ORDER BY created_at DESC"
        ).fetchall()
    return jsonify({"keys": [dict(r) for r in rows]})

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVER] Running on port {port}")
    app.run(host="0.0.0.0", port=port)
