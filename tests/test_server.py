import base64
import pytest

import sys
import os
import sqlite3

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from server import get_user_salt, app


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


def test_create_user(client):
    # Test case for creating a new user with valid data
    data = {"email": "test@example.com", "password": "password"}
    response = client.post("/users", json=data)
    assert response.status_code == 201  # Created


def test_get_user_salt(client):
    # Test case for retrieving a salt from the database for a specific user
    id = 999
    salt = b"\x14\x1cu\x1f/\x0e\xfe*\xd87\x1b\x1a)\x88\xba."
    db = sqlite3.connect("test_db.sqlite3")
    c = db.cursor()
    c.execute("drop table if exists user;")
    c.execute(
        "CREATE TABLE user (id INTEGER PRIMARY KEY, salt TEXT UNIQUE NOT NULL)"
    )
    db.commit()
    c.execute("INSERT INTO user (id, salt) VALUES (?, ?)", (id, salt))
    db.commit()
    retrieved = get_user_salt(id, db)
    assert retrieved == salt


def test_authenticate_user(client):
    # Test case for valid credentials
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.get("/", headers={"Authorization": credentials})
    assert response.status_code == 200  # OK


def test_authenticate_user_invalid(client):
    # Test case for invalid credentials
    response = client.get(
        "/passwords", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401  # Unauthorized


def test_requires_auth(client):
    # Test case for accessing protected route without authentication
    response = client.post("/passwords", json={})
    assert response.status_code == 401  # Unauthorized


def test_create_user_missing_data(client):
    # Test case for creating a user with missing data
    response = client.post("/users", json={})
    assert response.status_code == 400  # Bad request


def test_create_user_existing_email(client):
    # Test case for creating a user with existing email
    data = {"username": "test@example.com", "password": "password"}
    response = client.post("/users", json=data)
    assert response.status_code == 400  # Bad request


def test_passwords_put(client):
    # Testing PUT request
    response = client.put("/passwords")
    assert response.status_code == 405  # Method not allowed


def test_passwords_missing_data(client):
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.post(
        "/passwords", json={}, headers={"Authorization": credentials}
    )
    assert response.status_code == 400  # Bad request


def test_password_create(client):
    data = {
        "title": "Test Title",
        "url": "http://example.com",
        "username": "test_user",
        "password": "test_password",
        "note": "Test note",
    }
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.post(
        "/passwords", json=data, headers={"Authorization": credentials}
    )
    assert response.status_code == 201  # Created
