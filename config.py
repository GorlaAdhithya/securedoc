import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Set SECRET_KEY in the environment for production (keeps sessions valid across restarts).
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")

    MAX_UPLOAD_MB = 20
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024 + 4096  # small allowance for form fields

    # Encrypted files are deleted automatically after this many seconds.
    ENCRYPTED_TTL_SECONDS = 15 * 60
    CLEANUP_INTERVAL_SECONDS = 60

    # Password policy
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128

    # Simple per-IP rate limit for /encrypt
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_WINDOW_SECONDS = 60

    # File handling
    MAX_IMAGE_PIXELS = 60_000_000      # reject decompression bombs
    MAX_TEXT_CHARS = 2_000_000         # text files are rendered into PDF pages
    MAX_TEXT_PAGES = 400

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"