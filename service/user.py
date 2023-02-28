import base64
import hashlib
import hmac

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.user import UserDAO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def get_all(self):
        # if filters.get("director_id") is not None:
        #     movies = self.dao.get_by_director_id(filters.get("director_id"))
        # elif filters.get("genre_id") is not None:
        #     movies = self.dao.get_by_genre_id(filters.get("genre_id"))
        # elif filters.get("year") is not None:
        #     movies = self.dao.get_by_year(filters.get("year"))
        # else:
        #     movies = self.dao.get_all()
        return self.dao.get_all() #movies

    def create(self, user_d):
        user_d['password'] = self.get_hash(user_d.get('password'))
        return self.dao.create(user_d)

    def update(self, user_d):
        user_d['password'] = self.get_hash(user_d.get('password'))
        self.dao.update(user_d)
        return self.dao

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password_hash, other_password):
        return hmac.compare_digest(
            password_hash,
            self.get_hash(other_password)
        )