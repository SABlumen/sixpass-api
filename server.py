from flask import (
    Flask,
    g,
    request,
    jsonify,
    make_response,
    render_template,
)
import sqlite3
import argon2
from datetime import datetime, timedelta
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

app = Flask(__name__)
app.secret_key = "notsafe"


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
def get_user_salt(id, db):
    c = db.cursor()
    salt = c.execute("SELECT salt FROM user where id = ?", (id,)).fetchone()[0]
    return salt


def encryptor(data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES_MODE, iv)
    ciphertext = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return iv + ciphertext


def decryptor(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:AES_BLOCK_SIZE]
    ciphertext = encrypted_data[AES_BLOCK_SIZE:]
    cipher = AES.new(key, AES_MODE, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    return decrypted_data


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("db.sqlite3")
        g.db.row_factory = sqlite3.Row
        g.db.set_trace_callback(print)
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html"), 200


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
    salt = str(get_random_bytes(16))
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


@app.route("/passwords", methods=["GET", "POST"])
@requires_auth
def passwords():
    if request.method == "GET":
        db = get_db()
        try:
            password_list = db.execute(
                "SELECT * FROM passwords where id = ?", (g.user_id)
            ).fetchall()
        except sqlite3.IntegrityError:
            return jsonify({"msg": "No passwords stored for this user."}), 200

    elif request.method == "POST":
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
            db.execute(
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

            return jsonify({"msg": "Password stored successfully."}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Invalid request method."}), 405


if __name__ == "__main__":
    app.run(debug=True)
