import jwt
from flask import request
from flask_restx import abort

from constants import JWT_SECRET, JWT_ALGO


def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer')[-1].strip()

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        except Exception as e:
            print('JWT decode exception', e)
            abort(401)

        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer')[-1].strip()

        try:
            user = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            if user['role'] != 'admin':
                abort(401)

        except Exception as e:
            print('JWT decode exception', e)
            abort(401)

        return func(*args, **kwargs)

    return wrapper
