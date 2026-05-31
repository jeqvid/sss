"""
key_server.py — persistent PostgreSQL version
=============================================
Install: python -m pip install flask psycopg2-binary

Environment variables:
    BOT_SECRET   — must match discord_bot.py
    DATABASE_URL — PostgreSQL connection string (from Supabase)
"""

from flask import Flask, request, jsonify
import os, secrets, string
from datetime import datetime, timedelta, timezone

app        = Flask(__name__)
BOT_SECRET = os.environ.get("BOT_SECRET", "changeme123")
DB_URL     = os.environ.get("DATABASE_URL")

# ── DB driver: PostgreSQL if DATABASE_URL set, else SQLite ────────────────────
if DB_URL:
    import psycopg2
    from psycopg2.extras import RealDictCursor

    def get_db():
        conn = psycopg2.connect(DB_URL, sslmode="require")
        return conn

    PH = "%s"   # PostgreSQL placeholder
    print("[DB] Using PostgreSQL")
else:
    import sqlite3
    DB_FILE = "keys.db"

    def get_db():
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    PH = "?"    # SQLite placeholder
    print("[DB] Using SQLite (data will be lost on Render restart — set DATABASE_URL!)")

# ── Duration map ──────────────────────────────────────────────────────────────
DURATIONS = {
    "3min":  timedelta(minutes=3),
    "30min": timedelta(minutes=30),
    "1d":    timedelta(days=1),
    "3d":    timedelta(days=3),
    "1w":    timedelta(weeks=1),
    "1m":    timedelta(days=30),
    "perma": None,
}
DURATION_LABELS = {
    "3min":  "3 Minutes",
    "30min": "30 Minutes",
    "1d":    "1 Day",
    "3d":    "3 Days",
    "1w":    "1 Week",
    "1m":    "1 Month",
    "perma": "Permanent",
}

# ── DB init ───────────────────────────────────────────────────────────────────

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key        TEXT PRIMARY KEY,
                hwid       TEXT    DEFAULT NULL,
                duration   TEXT    DEFAULT 'perma',
                expires_at TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP NOT NULL,
                bound_at   TIMESTAMP DEFAULT NULL,
                note       TEXT    DEFAULT NULL,
                revoked    BOOLEAN DEFAULT FALSE
            )
        """)
        conn.commit()
    print("[DB] Ready")

def row_to_dict(row):
    if row is None:
        return None
    if hasattr(row, 'keys'):   # psycopg2 RealDictRow or sqlite3.Row
        return dict(row)
    return dict(row)

def fetch_one(cur, query, params=()):
    cur.execute(query, params)
    row = cur.fetchone()
    return row_to_dict(row) if row else None

def make_key() -> str:
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "GTAG-" + "-".join(parts)

def now_utc():
    return datetime.now(timezone.utc)

def is_expired(expires_at) -> bool:
    if not expires_at:
        return False
    try:
        if isinstance(expires_at, str):
            exp = datetime.fromisoformat(expires_at)
        else:
            exp = expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False

# ── Auth ──────────────────────────────────────────────────────────────────────

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
    expires_at = (now_utc() + delta) if delta else None
    key        = make_key()

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO keys (key, duration, expires_at, created_at, note) VALUES ({PH},{PH},{PH},{PH},{PH})",
            (key, duration, expires_at, now_utc(), note)
        )
        conn.commit()

    print(f"[KEY] Generated: {key} ({DURATION_LABELS[duration]})")
    return jsonify({
        "key":        key,
        "duration":   DURATION_LABELS[duration],
        "expires_at": expires_at.isoformat() if expires_at else None
    })

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True) or {}
    key  = data.get("key",  "").strip().upper()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Missing key or HWID."})

    with get_db() as conn:
        cur = conn.cursor()
        if DB_URL:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        row = fetch_one(cur, f"SELECT * FROM keys WHERE key = {PH}", (key,))

        if not row:
            return jsonify({"valid": False, "message": "Key not found."})
        if row["revoked"]:
            return jsonify({"valid": False, "message": "Key has been revoked."})
        if is_expired(row["expires_at"]):
            return jsonify({"valid": False, "message": "Key has expired."})

        if row["hwid"] is None:
            delta      = DURATIONS.get(row["duration"] or "perma")
            expires_at = (now_utc() + delta) if delta else None
            cur.execute(
                f"UPDATE keys SET hwid={PH}, bound_at={PH}, expires_at={PH} WHERE key={PH}",
                (hwid, now_utc(), expires_at, key)
            )
            conn.commit()
            label = DURATION_LABELS.get(row["duration"] or "perma", "Permanent")
            print(f"[KEY] Activated: {key} ({label}) → {hwid[:12]}…")
            return jsonify({"valid": True, "message": f"Key activated! ({label})"})

        if row["hwid"] == hwid:
            return jsonify({"valid": True, "message": "OK"})

        return jsonify({"valid": False, "message": "Key is invalid."})

@app.route("/revoke", methods=["POST"])
def revoke():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    key = data.get("key", "").strip().upper()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE keys SET revoked=TRUE WHERE key={PH}", (key,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/reset", methods=["POST"])
def reset_hwid():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    key = data.get("key", "").strip().upper()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE keys SET hwid=NULL, bound_at=NULL WHERE key={PH}", (key,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/list", methods=["POST"])
def list_keys():
    data = request.get_json(silent=True) or {}
    if not auth(data):
        return jsonify({"error": "unauthorized"}), 403
    with get_db() as conn:
        cur = conn.cursor()
        if DB_URL:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT key, hwid, duration, expires_at, created_at, bound_at, note, revoked FROM keys ORDER BY created_at DESC")
        rows = cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("expires_at", "created_at", "bound_at"):
            if d.get(k) and not isinstance(d[k], str):
                d[k] = d[k].isoformat()
        result.append(d)
    return jsonify({"keys": result})

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVER] Running on port {port}")
    app.run(host="0.0.0.0", port=port)
