import base64
import pytest

import sys
import os
import sqlite3

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from createdb import create_db
from server import get_user_salt, app

create_db()


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


def test_create_user(client):
    # Test case for creating a new user with valid data
    data = {"email": "test@example.com", "password": "password"}
    response = client.post("/users", json=data)
    assert response.status_code == 201  # Created


def test_get_user_salt():
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
    # Test for creating a user with an existing email
    data = {"username": "test@example.com", "password": "password"}
    response = client.post("/users", json=data)
    assert response.status_code == 400  # Bad request


def test_passwords_missing_data(client):
    # Test for creating a password while not providing data
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.post(
        "/passwords", json={}, headers={"Authorization": credentials}
    )
    assert response.status_code == 400  # Bad request


def test_passwords_post(client):
    # Test for creating a password
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
    assert response.json["password_id"]


def test_passwords_get(client):
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.get("/passwords", headers={"Authorization": credentials})
    assert response.status_code == 200  # OK


def test_passwords_put_missing_id(client):
    # Test case for receiving an error if no password id is provided
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    response = client.put(
        "/passwords",
        json={},
        headers={"Authorization": credentials},
    )
    assert response.status_code == 400  # Bad Request


def test_passwords_put_and_delete(client):
    # Test case for updating a password with valid data
    # Craft a POST request to create password to be used for PUT later
    create_data = {
        "title": "Test Password for PUT",
        "url": "http://example.com",
        "username": "test_user",
        "password": "test_password",
        "note": "Test note for PUT",
    }
    credentials = "Basic " + base64.b64encode(
        b"test@example.com:password"
    ).decode("utf-8")
    create_response = client.post(
        "/passwords", json=create_data, headers={"Authorization": credentials}
    )
    assert create_response.json["password_id"]
    pw_id = create_response.json["password_id"]
    assert create_response.status_code == 201  # Created

    # Craft the PUT request
    update_data = {
        "title": "Updated Title",
        "url": "http://example.com/updated",
        "username": "updated_user",
        "password": "updated_password",
        "note": "Updated note",
    }
    response = client.put(
        f"/passwords?id={pw_id}",
        json=update_data,
        headers={"Authorization": credentials},
    )
    assert response.status_code == 200  # OK

    # Control section for verifying correct results
    control_response = client.get(
        "/passwords", headers={"Authorization": credentials}
    )
    assert control_response.status_code == 200  # OK

    passwords_data = control_response.json
    assert f"{pw_id}" in passwords_data
    updated_password = passwords_data[f"{pw_id}"]
    assert updated_password["title"] == update_data["title"]
    assert updated_password["url"] == update_data["url"]
    assert updated_password["username"] == update_data["username"]
    assert updated_password["note"] == update_data["note"]
    # Control that the password is decrypted correctly
    assert updated_password["password"] == update_data["password"]

    # Delete the password
    control_response = client.delete(
        f"/passwords?id={pw_id}", headers={"Authorization": credentials}
    )
    assert control_response.status_code == 200  # OK
