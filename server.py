from flask import (
    Flask,
    g,
    request,
    jsonify,
    render_template,
)
import sqlite3
import argon2
from typing import Union
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from functools import wraps
from base64 import b64encode, b64decode

# Key derivation parameters
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

# AES parameters
AES_BLOCK_SIZE = 16
AES_MODE = AES.MODE_CBC

# Create Flask app
app = Flask(__name__)
app.secret_key = "notsafe"


# Function to authenticate the user performing the current request
def authenticate_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return False
    try:
        auth_type, credentials = auth_header.split(" ")
        if auth_type.lower() != "basic":
            return False
        decoded_credentials = b64decode(credentials).decode("utf-8")
        email, password = decoded_credentials.split(":", 1)

        db = get_db()
        user = db.execute(
            "SELECT id, password FROM user WHERE email = ?", (email,)
        ).fetchone()
        id = user[0]
        hash = user[1]

        ph = argon2.PasswordHasher()
        if user and ph.verify(hash, password):
            g.user_id = id
            g.password = password
            return True
    except Exception as e:
        print("Error:", e)
    return False


# Decorator to protect routes with HTTP authentication header
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not authenticate_user():
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


# Function to derive a key for AES encryption from a password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)


# Function to get user salt from db. Specify their id and provide the db.
def get_user_salt(id: Union[str, int], db: sqlite3.Connection) -> bytes:
    c = db.cursor()
    salt = c.execute("SELECT salt FROM user where id = ?", (id,)).fetchone()[0]
    return salt


# Function to encrypt password using AES, CBC mode and PKCS7 padding
def encryptor(data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES_MODE, iv)
    ciphertext = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return iv + ciphertext


# Function to decrypt password using AES, CBC mode and PKCS7 padding
def decryptor(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:AES_BLOCK_SIZE]
    ciphertext = encrypted_data[AES_BLOCK_SIZE:]
    cipher = AES.new(key, AES_MODE, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    return decrypted_data


# Database connection
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("db.sqlite3")
        g.db.row_factory = sqlite3.Row
        g.db.set_trace_callback(print)
    return g.db


# Database closing
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Route to render index.html as default
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html"), 200


# Route to create new user
@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json()
    try:
        email = data["email"]
        password = data["password"]
    except KeyError as e:
        missing = str(e).strip("'")
        return jsonify({"error": f"Missing {missing}. Try again."}), 400

    ph = argon2.PasswordHasher()
    hashed = ph.hash(password)
    salt = get_random_bytes(16)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO user (email, password, salt) VALUES (?, ?, ?)",
            (email, hashed, salt),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "Email already exists."}), 400
    return jsonify({"msg": "Successfully created user."}), 201


# Function to get all passwords for a user
def passwords_get():
    db = get_db()
    try:
        password_list = db.execute(
            "SELECT * FROM password where user_id = ?", (g.user_id,)
        ).fetchall()
        dict = {}
        for row in password_list:
            dict[row[0]] = {
                "title": row[2],
                "url": row[3],
                "username": row[4],
                "password": decryptor(
                    b64decode(row[5]),
                    derive_key(
                        g.password.encode(), get_user_salt(g.user_id, db)
                    ),
                ).decode("utf-8"),
                "note": row[6],
                "created": row[7],
                "accessed": row[8],
                "modified": row[9],
            }
        return jsonify(dict), 200
    except sqlite3.IntegrityError:
        return jsonify({"msg": "No passwords stored for this user."}), 200


# Function to create a new password
def passwords_post():
    try:
        data = request.get_json()
        title = data["title"]
        url = data["url"]
        username = data["username"]
        password = data["password"].encode("utf-8")
        note = data["note"]
    except KeyError as e:
        missing = str(e).strip("'")
        return jsonify({"error": f"Missing data field {missing}."}), 400
    try:
        db = get_db()
        salt = get_user_salt(g.user_id, db)
        DK = derive_key(g.password.encode(), salt)
        encrypted_password = encryptor(bytes(password), DK)

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO password (user_id, title, url, username, password, note, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                g.user_id,
                title,
                url,
                username,
                b64encode(encrypted_password).decode("utf-8"),
                note,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        db.commit()
        password_id = cursor.lastrowid

        return (
            jsonify(
                {
                    "msg": "Password stored successfully.",
                    "password_id": f"{password_id}",
                }
            ),
            201,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Function to update a password given its ID
def passwords_put(password_id: str) -> tuple:
    try:
        data = request.get_json()
        db = get_db()

        existing_password = db.execute(
            "SELECT id from password WHERE id=? AND user_id=?",
            (password_id, g.user_id),
        ).fetchone()
        if not existing_password:
            return jsonify({"error": "Password not found."}), 400

        update_fields = {}
        allow_fields = ["title", "url", "username", "password", "note"]
        for field in allow_fields:
            if field in data:
                update_fields[field] = data[field]

        if "password" in update_fields:
            salt = get_user_salt(g.user_id, db)
            DK = derive_key(g.password.encode(), salt)
            encrypted_password = encryptor(
                update_fields["password"].encode(), DK
            )
            update_fields["password"] = b64encode(encrypted_password).decode(
                "utf-8"
            )

        update_fields["modified"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        query = "UPDATE password SET "
        query += ", ".join([f"{key} = ?" for key in update_fields])
        query += " WHERE id = ? AND user_id = ?"

        db.execute(
            query, tuple(update_fields.values()) + (password_id, g.user_id)
        )
        db.commit()

        return (
            jsonify(
                {
                    "msg": "Password updated successfully.",
                    "password_id": f"{password_id}",
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Function to delete a password given its ID
def passwords_delete(password_id):
    try:
        db = get_db()
        db.execute(
            "DELETE FROM password WHERE id=? AND user_id=?",
            (password_id, g.user_id),
        )
        db.commit()

        return jsonify({"msg": "Password deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Route to get passwords and post new password
@app.route("/passwords", methods=["GET", "POST", "PUT", "DELETE"])
@requires_auth
def passwords():
    if request.method == "GET":
        return passwords_get()
    elif request.method == "POST":
        return passwords_post()
    elif request.method == "PUT":
        password_id = request.args.get("id")
        if not password_id:
            return (
                jsonify({"error": "Missing password ID."}),
                400,
            )
        return passwords_put(password_id)
    elif request.method == "DELETE":
        password_id = request.args.get("id")
        if not password_id:
            return (
                jsonify({"error": "Missing password ID."}),
                400,
            )
        return passwords_delete(password_id)

    return jsonify({"error": "Invalid request method."}), 405


# Run the server if executed from interactive python
if __name__ == "__main__":
    app.run(debug=True)
