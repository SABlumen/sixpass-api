# sixpass-api
A stateless password manager web-API using Flask and AES encryption.

# SixPass API Documentation
by Sixten Arild Blumensaadt, siggerab@gmail.com
## Introduction

This document outlines the functionality and usage of the SixPass Password Manager API. The API allows users to manage their passwords securely. This includes creating, updating, and deleting passwords, as well as associating passwords with labels for better organization.

## Authentication
The API uses HTTP Basic Authentication to authenticate users on all routes requiring auth. Users therefore need to include their credentials in the Authorization header of their requests to these routes.

### Users' master password and credential security

The API verifies user credentials against stored credentials in the database using Argon2 hashing. The credentials that users store are AES encrypted with a key size of 256 bits using the master password and per-user salting. All AES encryption is done in CBC mode using cryptographically randomized initialization vectors.

## Endpoints

### 1. `/users`

#### POST `/users`

- **Description:** Create a new user.
- **Request Body:** JSON object containing email and password.
- **Response:** JSON object with a success message or an error message if the email already exists.

### 2. `/passwords`

#### GET `/passwords`

- **Description:** Get all passwords associated with the authenticated user.
- **Response:** JSON object containing a dict with the key being the password_id and the value being a dict with the password information.

#### POST `/passwords`

- **Description:** Create a new password.
- **Request Body:** JSON object containing title, url, username, password, and note. Everything but the title and url can be left empty, but the keys still need to be provided in the JSON object.
- **Response:** JSON object with a success message or an error message. Also with a password_id key containing the ID of the password created.

#### PUT `/passwords?id=<password_id>`

- **Description:** Update an existing password.
- **Request Body:** JSON object containing the fields to update. You only need to provide the key(s) of the field(s) to update.
- **Response:** JSON object with a success message or an error message. Also with a password_id key containing the ID of the password created.

#### DELETE `/passwords?id=<password_id>`

- **Description:** Delete a password by its ID. The ID can be obtained from other endpoints, see GET, POST for /passwrods.
- **Response:** JSON object with a success message or an error message.

### 3. `/labels`

#### GET `/labels`

- **Description:** Get all labels associated with the authenticated user.
- **Response:** JSON object containing a list of labels.

#### POST `/labels`

- **Description:** Create a new label.
- **Request Body:** JSON object containing name.
- **Response:** JSON object with a success message or an error message.

#### PUT `/labels/<label_id>`

- **Description:** Update an existing label by ID.
- **Request Body:** JSON object containing name.
- **Response:** JSON object with a success message or an error message.

#### DELETE `/labels/<label_id>`

- **Description:** Delete a label by ID.
- **Response:** JSON object with a success message or an error message.

#### POST `/labels/associate`

- **Description:** Associate a label with a password.
- **Request Body:** JSON object containing label_id and password_id.
- **Response:** JSON object with a success message or an error message.

### 4. `/labels/<label_id>/passwords`

#### GET `/labels/<label_id>/passwords`

- **Description:** Get all passwords associated with a label.
- **Response:** JSON object containing a list of passwords.

### 5. `/passwords/<password_id>/labels`

#### GET `/passwords/<password_id>/labels`

- **Description:** Get all labels associated with a password.
- **Response:** JSON object containing a list of labels.

## Error Handling

The API returns appropriate HTTP status codes along with error messages in JSON format for any errors encountered during requests.

## Requirements
A few pip packages are required to run the Flask app.\
\
pip3 install Flask argon2-cffi pycryptodome pytest

If you are on Linux, you might need to install these via your package manager.

## Usage

To use the Password Manager API, first start the Flask app. Then send HTTP requests to the specified endpoints with appropriate authentication credentials and request bodies where required.

Example creating a user with curl:\
curl -X POST -H "Content-Type: application/json" -d '{"email": "test@example.com","password": "test123"}' http://localhost:5000/users

## Disclaimer
Do not run this in a production environment. This is a testing app made for testing and educational purposes. There are no guarantees for anything. It is also designed to be run locally with a reverse proxy or with HTTPS implemented. HTTPS IS NOT IMPLEMENTED.

## Known issues
- Deleting label associations is not supported yet.
- Deleting a password that is associated with a label does not work. The association needs deleting first and then the password can be deleted.

## Further development
- Needs further security. HTTPS/reverse proxy.
- Full CRUD for label associations should be implemented.
- More routes with GET-method for passwords based on user-provided filters
- Deleting a password should delete its associations first because of FK constraints.
- A basic CLI for users to take inspiration from or utilize in the terminal.
- More detailed pytests. More standardization, better test database environment, mocking, wider test coverage.
- Detailed documentation
- Refactoring repeated code in testing file
