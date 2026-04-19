# This file is INTENTIONALLY INSECURE — used as a test fixture only.
# Do not use any of this code in real projects.

import os
import pickle
import hashlib
import random
import subprocess
from flask import Flask

app = Flask(__name__)

# S001 — hardcoded secrets (various forms)
password = "hunter2"
api_key = "sk-1234567890abcdef"
secret: str = "my_super_secret"
self_password = "notapassword123"
config = {}
config["api_key"] = "hardcoded_api_key_here"


def connect():
    db_password = "postgres_root_pass"


# S002 — dangerous function calls
def run_user_input(user_input):
    eval(user_input)
    exec(user_input)
    os.system("ls " + user_input)
    subprocess.run(user_input, shell=True)


# S002 — pickle deserialisation
def load_data(f):
    return pickle.loads(f.read())


# S003 — weak crypto
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def generate_token():
    return str(random.randint(100000, 999999))


# S004 — SQL injection
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query


def search(term):
    query = f"SELECT * FROM products WHERE name = {term}"
    return query


def delete_record(table, record_id):
    query = "DELETE FROM {} WHERE id = {}".format(table, record_id)
    return query


# S005 — debug artefacts
HOST = "192.168.1.50"


if __name__ == "__main__":
    app.run(debug=True)
