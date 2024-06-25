import base64
import hashlib
import secrets
from datetime import datetime, timedelta

from cryptography.fernet import Fernet
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Clave secreta para encriptar el identificador de sesión
SECRET_KEY = b"GPimJlIp7j1p-dsu9xvF2jhU8lL6cvzovhNH2CMRtmI="

# Base de datos de usuarios
users = []

# Base de datos de sesiones
sessions = {}


# Función para generar un hash de una cadena
def hash_string(string):
    return hashlib.sha256(string.encode()).hexdigest()


# Función para generar un identificador de sesión
def generate_session_id():
    return secrets.token_hex(16)


# Función para encriptar un valor
def encrypt_value(value):
    f = Fernet(SECRET_KEY)
    return f.encrypt(value.encode()).decode()


# Función para desencriptar un valor
def decrypt_value(value):
    f = Fernet(SECRET_KEY)
    return f.decrypt(value.encode()).decode()


# Función para verificar que el usuario exista en la base de datos
def verify_user(username, password):
    for user in users:
        if user["username"] == username and user["password"] == hash_string(password):
            return user
    return None


# Función para verificar que el identificador de sesión sea válido
def verify_session(session_id):
    return session_id in sessions


# Función para obtener el usuario a partir del identificador de sesión
def get_user(session_id):
    return sessions[session_id]


# Función para crear un usuario
def create_user(username, email, password):
    user = {
        "id": len(users) + 1,
        "username": username,
        "email": email,
        "password": hash_string(password),
    }
    users.append(user)
    return user


# Función para crear una sesión
def create_session(user):
    session_id = generate_session_id()
    sessions[session_id] = user
    return session_id


# Función para eliminar una sesión
def delete_session(session_id):
    del sessions[session_id]


# Función para obtener el identificador de sesión de una cookie
def get_session_id_from_cookie():
    session_id = request.cookies.get("session_id")
    if session_id:
        return decrypt_value(session_id)
    return None


# Función para crear una cookie con el identificador de sesión
def create_session_cookie(session_id):
    session_id_encrypted = encrypt_value(session_id)
    response = make_response(jsonify({"message": "Sesión iniciada"}))
    # Set the cookie with SameSite=None and Secure
    response.set_cookie(
        "session_id",
        session_id_encrypted,
        httponly=True,  # Optional, but recommended for security
        secure=True,  # Required for SameSite=None
        samesite="None",  # Setting SameSite to None
        expires=datetime.now() + timedelta(days=1),
    )  # Optional: Set cookie expiry
    return response


# Función para eliminar la cookie con el identificador de sesión
def delete_session_cookie():
    response = make_response(jsonify({"message": "Sesión cerrada"}))
    response.set_cookie("session_id", "", expires=0)
    return response


# Función para verificar que el usuario esté autenticado
def verify_authentication():
    session_id = get_session_id_from_cookie()
    if session_id and verify_session(session_id):
        return True
    return False


# Función para obtener el usuario autenticado
def get_authenticated_user():
    session_id = get_session_id_from_cookie()
    if session_id and verify_session(session_id):
        return get_user(session_id)
    return None


# Ruta para crear un usuario
@app.route("/users", methods=["POST"])
def create_user_route():
    data = request.get_json()
    user = create_user(data["username"], data["email"], data["password"])
    return jsonify(user)


def decode_credentials(encoded_credentials):
    decode_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
    return decode_credentials.split(":")


def verify_authentication():
    auth_credetials = request.authorization
    if auth_credetials and auth_credetials.type == "basic":
        username, password = decode_credentials(
            str(auth_credetials.username), str(auth_credetials)[6:])
        return verify_user(username, password)
    else:
        raise Exception("Error de autenticación")

# Ruta para iniciar sesión


# @app.route("/login", methods=["POST"])
# def login_route():
#     data = request.get_json()
#     user = verify_user(data["username"], data["password"])
#     if user:
#         session_id = create_session(user)
#         return create_session_cookie(session_id)
#     return jsonify({"message": "Usuario o contraseña incorrectos"}), 401


# Ruta para cerrar sesión
@app.route("/logout", methods=["POST"])
def logout_route():
    session_id = get_session_id_from_cookie()
    if session_id:
        delete_session(session_id)
        return delete_session_cookie()
    return jsonify({"message": "No se ha iniciado sesión"}), 401


# Ruta para obtener el usuario autenticado
# @app.route("/me", methods=["GET"])
# def me_route():
#     if verify_authentication():
#         user = get_authenticated_user()
#         return jsonify(user)
#     return jsonify({"message": "No se ha iniciado sesión"}), 401

@app.route("/profile", methods=["GET"])
def me_route():
    try:
        user_data = verify_authentication()
        if user_data:
            return jsonify(user_data), 200
        return jsonify({"message": "Credenciales incorrectas. Se requiere autenticacion de un usuario existente"}), 401
    except Exception as e:
        return jsonify({"message": str(e)}), 401


if __name__ == "__main__":
    app.run(debug=True)
