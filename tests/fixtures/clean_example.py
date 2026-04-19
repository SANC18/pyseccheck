# This file is CLEAN — all security practices are correct.
# pyseccheck should produce zero findings on this file.

import os
import hashlib
import secrets
import subprocess

# Correct: load from environment
password = os.environ.get("DB_PASSWORD")
api_key  = os.environ.get("API_KEY")

# Correct: placeholder / empty strings are not flagged
debug_token = ""
example_key = "changeme"

# Correct: strong hash
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

# Correct: cryptographically secure random
def generate_token() -> str:
    return secrets.token_hex(32)

# Correct: subprocess without shell=True
def list_files(directory: str) -> None:
    subprocess.run(["ls", "-la", directory], check=True)
