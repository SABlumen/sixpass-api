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

app = Flask(__name__)
app.secret_key = "notsafe"


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
def root():
    return render_template("index.html"), 200
