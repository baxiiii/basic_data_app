from functools import wraps
import sqlite3
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

API_KEY = "api_warehouse_student_key_1234567890abcdef"
DB_PATH = "warehouse.db"

app = Flask(__name__)


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        header_key = request.headers.get("X-API-Key", "")
        auth_header = request.headers.get("Authorization", "")
        bearer_key = ""
        if auth_header.lower().startswith("bearer "):
            bearer_key = auth_header.split(" ", 1)[1].strip()
        if header_key != API_KEY and bearer_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)

    return wrapper


def fetch_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username, role, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


@app.route("/api/v1/users", methods=["GET"])
def list_users():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, username, role, created_at, updated_at FROM users ORDER BY id"
        ).fetchall()
    return jsonify([row_to_dict(row) for row in rows]), 200


@app.route("/api/v1/users", methods=["POST"])
def create_user():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role", "student")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    password_hash = generate_password_hash(password)

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (username, password_hash, role),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify(fetch_user_by_id(user_id)), 201


@app.route("/api/v1/users/<int:user_id>", methods=["GET"])
def get_user(user_id: int):
    user = fetch_user_by_id(user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify(user), 200


@app.route("/api/v1/users/<int:user_id>", methods=["PUT"])
def update_user(user_id: int):
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role")

    if not any([username, password, role]):
        return jsonify({"error": "no fields to update"}), 400

    updates = []
    values = []

    if username:
        updates.append("username = ?")
        values.append(username)
    if password:
        updates.append("password_hash = ?")
        values.append(generate_password_hash(password))
    if role:
        updates.append("role = ?")
        values.append(role)

    updates.append("updated_at = CURRENT_TIMESTAMP")

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                (*values, user_id),
            )
            if cursor.rowcount == 0:
                return jsonify({"error": "user not found"}), 404
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify(fetch_user_by_id(user_id)), 200


@app.route("/api/v1/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id: int):
    with get_connection() as connection:
        cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if cursor.rowcount == 0:
            return jsonify({"error": "user not found"}), 404
    return "", 204


@app.route("/api/v1/users/login", methods=["POST"])
def login_user():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    user = row_to_dict(row)
    user.pop("password_hash", None)
    return jsonify({"message": "login successful", "user": user}), 200


def fetch_log_by_id(log_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, title, description, priority, status, user_id, created_at, updated_at
            FROM maintenance_logs
            WHERE id = ?
            """,
            (log_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


@app.route("/api/v1/logs", methods=["GET"])
@require_api_key
def list_logs():
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, title, description, priority, status, user_id, created_at, updated_at
            FROM maintenance_logs
            ORDER BY id
            """
        ).fetchall()
    return jsonify([row_to_dict(row) for row in rows]), 200


@app.route("/api/v1/logs", methods=["POST"])
@require_api_key
def create_log():
    payload = request.get_json(silent=True) or {}
    title = payload.get("title")
    description = payload.get("description")
    priority = payload.get("priority")
    status = payload.get("status")
    user_id = payload.get("user_id")

    if not all([title, description, priority, status]):
        return jsonify({"error": "title, description, priority, and status are required"}), 400

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO maintenance_logs
                (title, description, priority, status, user_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (title, description, priority, status, user_id),
        )
        log_id = cursor.lastrowid

    return jsonify(fetch_log_by_id(log_id)), 201


@app.route("/api/v1/logs/<int:log_id>", methods=["GET"])
@require_api_key
def get_log(log_id: int):
    log = fetch_log_by_id(log_id)
    if not log:
        return jsonify({"error": "log not found"}), 404
    return jsonify(log), 200


@app.route("/api/v1/logs/<int:log_id>", methods=["PUT"])
@require_api_key
def update_log(log_id: int):
    payload = request.get_json(silent=True) or {}
    title = payload.get("title")
    description = payload.get("description")
    priority = payload.get("priority")
    status = payload.get("status")
    user_id = payload.get("user_id")

    if not any([title, description, priority, status, user_id is not None]):
        return jsonify({"error": "no fields to update"}), 400

    updates = []
    values = []

    if title:
        updates.append("title = ?")
        values.append(title)
    if description:
        updates.append("description = ?")
        values.append(description)
    if priority:
        updates.append("priority = ?")
        values.append(priority)
    if status:
        updates.append("status = ?")
        values.append(status)
    if user_id is not None:
        updates.append("user_id = ?")
        values.append(user_id)

    updates.append("updated_at = CURRENT_TIMESTAMP")

    with get_connection() as connection:
        cursor = connection.execute(
            f"UPDATE maintenance_logs SET {', '.join(updates)} WHERE id = ?",
            (*values, log_id),
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "log not found"}), 404

    return jsonify(fetch_log_by_id(log_id)), 200


@app.route("/api/v1/logs/<int:log_id>", methods=["DELETE"])
@require_api_key
def delete_log(log_id: int):
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM maintenance_logs WHERE id = ?", (log_id,)
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "log not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
