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
from datetime import datetime, timedelta, timezone

app        = Flask(__name__)
DB_FILE    = "keys.db"
BOT_SECRET = os.environ.get("BOT_SECRET", "dtW8F4Aa")

# ── Duration map ──────────────────────────────────────────────────────────────
DURATIONS = {
    "1d":    timedelta(days=1),
    "3d":    timedelta(days=3),
    "1w":    timedelta(weeks=1),
    "1m":    timedelta(days=30),
    "perma": None,
}
DURATION_LABELS = {
    "1d":    "1 Day",
    "3d":    "3 Days",
    "1w":    "1 Week",
    "1m":    "1 Month",
    "perma": "Permanent",
}

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
                duration   TEXT    DEFAULT 'perma',
                expires_at TEXT    DEFAULT NULL,
                created_at TEXT    NOT NULL,
                bound_at   TEXT    DEFAULT NULL,
                note       TEXT    DEFAULT NULL,
                revoked    INTEGER DEFAULT 0
            )
        """)
        # Migrate old DB that lacks duration/expires_at columns
        cols = [r[1] for r in conn.execute("PRAGMA table_info(keys)").fetchall()]
        if "duration" not in cols:
            conn.execute("ALTER TABLE keys ADD COLUMN duration TEXT DEFAULT 'perma'")
        if "expires_at" not in cols:
            conn.execute("ALTER TABLE keys ADD COLUMN expires_at TEXT DEFAULT NULL")
    print(f"[DB] Ready — {DB_FILE}")

def make_key() -> str:
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "GTAG-" + "-".join(parts)

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def is_expired(expires_at) -> bool:
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False

# ── Auth helper ───────────────────────────────────────────────────────────────

def auth(data):
    return data.get("secret") == BOT_SECRET

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/generate", methods=["POST"])
def generate():
    data     = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403

    duration = data.get("duration", "perma").lower()
    if duration not in DURATIONS:
        return jsonify({"error": f"Invalid duration. Use: {', '.join(DURATIONS)}"}), 400

    note       = data.get("note", "")
    delta      = DURATIONS[duration]
    expires_at = (datetime.now(timezone.utc) + delta).isoformat() if delta else None
    key        = make_key()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO keys (key, duration, expires_at, created_at, note) VALUES (?, ?, ?, ?, ?)",
            (key, duration, expires_at, now_utc(), note)
        )
    print(f"[KEY] Generated: {key} ({DURATION_LABELS[duration]})")
    return jsonify({"key": key, "duration": DURATION_LABELS[duration], "expires_at": expires_at})

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
        if is_expired(row["expires_at"]):
            return jsonify({"valid": False, "message": "Key has expired."})

        if row["hwid"] is None:
            # First use — bind HWID, start expiry from now
            expires_at = row["expires_at"]
            delta      = DURATIONS.get(row["duration"] or "perma")
            if delta and not expires_at:
                expires_at = (datetime.now(timezone.utc) + delta).isoformat()

            conn.execute(
                "UPDATE keys SET hwid = ?, bound_at = ?, expires_at = ? WHERE key = ?",
                (hwid, now_utc(), expires_at, key)
            )
            label = DURATION_LABELS.get(row["duration"] or "perma", "Permanent")
            print(f"[KEY] Activated: {key} ({label}) → {hwid[:12]}…")
            return jsonify({"valid": True, "message": f"Key activated! ({label})"})

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
            "SELECT key, hwid, duration, expires_at, created_at, bound_at, note, revoked FROM keys ORDER BY created_at DESC"
        ).fetchall()
    return jsonify({"keys": [dict(r) for r in rows]})

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVER] Running on port {port}")
    app.run(host="0.0.0.0", port=port)
