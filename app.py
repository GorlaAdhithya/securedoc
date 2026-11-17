"""SecureDoc - Password Protected File Encryption System.

Encryption is applied INSIDE the PDF file using the standard PDF Security Handler
(the same mechanism used by password-protected e-Aadhaar PDFs). We use AES-256
(PDF revision 6), so any compliant reader (Adobe Acrobat, Chrome, Android/iOS
viewers) shows its own native "Enter password to open file" dialog.

Supported uploads:
  * PDF                      -> encrypted directly
  * Images (png, jpg, ...)   -> placed on a PDF page, then encrypted
  * Text files (txt, ...)    -> rendered into a PDF, then encrypted
  * Any other file           -> embedded unchanged inside an encrypted PDF
"""
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

import pikepdf
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import Config
from converters import ConversionError, kind_for, to_pdf_bytes

app = Flask(__name__)
app.config.from_object(Config)

# Never log request bodies / passwords. Keep logging at WARNING for werkzeug request lines only.
logging.getLogger("werkzeug").setLevel(logging.WARNING)

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.ENCRYPTED_FOLDER, exist_ok=True)

TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")
_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)

KIND_LABELS = {
    "pdf": "PDF document",
    "image": "Image (converted to a protected PDF)",
    "text": "Text file (converted to a protected PDF)",
    "file": "File (stored inside a protected PDF)",
}


# --------------------------------------------------------------------------- helpers
def _csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = _csrf_token


def _check_csrf():
    sent = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(403)


def _rate_limited(ip):
    now = time.time()
    with _rate_lock:
        q = _rate_hits[ip]
        while q and now - q[0] > Config.RATE_LIMIT_WINDOW_SECONDS:
            q.popleft()
        if len(q) >= Config.RATE_LIMIT_REQUESTS:
            return True
        q.append(now)
        return False


def validate_password(pw):
    """Return an error message, or None if the password is acceptable."""
    if len(pw) < Config.MIN_PASSWORD_LENGTH:
        return f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters."
    if len(pw) > Config.MAX_PASSWORD_LENGTH:
        return f"Password must be at most {Config.MAX_PASSWORD_LENGTH} characters."
    classes = sum([
        bool(re.search(r"[a-z]", pw)),
        bool(re.search(r"[A-Z]", pw)),
        bool(re.search(r"\d", pw)),
        bool(re.search(r"[^A-Za-z0-9]", pw)),
    ])
    if classes < 3:
        return "Use at least 3 of: lowercase, uppercase, numbers, symbols."
    return None


def _paths(token):
    return (os.path.join(Config.ENCRYPTED_FOLDER, f"{token}.pdf"),
            os.path.join(Config.ENCRYPTED_FOLDER, f"{token}.json"))


def _remove_token(token):
    for p in _paths(token):
        try:
            os.remove(p)
        except OSError:
            pass


def _load_meta(token):
    if not TOKEN_RE.match(token or ""):
        return None
    pdf_path, meta_path = _paths(token)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except (FileNotFoundError, ValueError):
        return None
    if time.time() > meta.get("expires", 0) or not os.path.exists(pdf_path):
        _remove_token(token)
        return None
    # Token must belong to the session that created it.
    if not hmac.compare_digest(meta.get("owner", ""), session.get("sid", "")):
        return None
    return meta


def cleanup_expired():
    now = time.time()
    for folder in (Config.ENCRYPTED_FOLDER, Config.UPLOAD_FOLDER):
        for name in os.listdir(folder):
            if name.startswith("."):
                continue
            path = os.path.join(folder, name)
            try:
                age = now - os.path.getmtime(path)
                limit = Config.ENCRYPTED_TTL_SECONDS if folder == Config.ENCRYPTED_FOLDER else 300
                if age > limit:
                    os.remove(path)
            except OSError:
                pass


def _cleanup_loop():
    while True:
        time.sleep(Config.CLEANUP_INTERVAL_SECONDS)
        try:
            cleanup_expired()
        except Exception:  # never let the janitor die
            pass


threading.Thread(target=_cleanup_loop, daemon=True).start()


@app.before_request
def _ensure_session():
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "img-src 'self' data:; frame-ancestors 'none'"
    )
    return resp


# --------------------------------------------------------------------------- routes
@app.route("/")
def intro():
    return render_template("intro.html")


@app.route("/accept", methods=["POST"])
def accept():
    _check_csrf()
    if request.form.get("agree") != "on":
        return redirect(url_for("intro"))
    session["agreed"] = True
    return redirect(url_for("app_page"))


@app.route("/app")
def app_page():
    if not session.get("agreed"):
        return redirect(url_for("intro"))
    return render_template("index.html", max_mb=Config.MAX_UPLOAD_MB,
                           min_len=Config.MIN_PASSWORD_LENGTH)


@app.route("/encrypt", methods=["POST"])
def encrypt():
    _check_csrf()
    if not session.get("agreed"):
        return jsonify(ok=False, error="Please accept the Terms & Conditions first."), 403
    if _rate_limited(request.remote_addr or "unknown"):
        return jsonify(ok=False, error="Too many requests. Please wait a minute and try again."), 429

    file = request.files.get("document")
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not file or not file.filename:
        return jsonify(ok=False, error="Please choose a file to upload."), 400

    safe_name = secure_filename(file.filename) or "document"
    ext = os.path.splitext(safe_name)[1].lstrip(".").lower()
    kind = kind_for(ext)

    if password != confirm:
        return jsonify(ok=False, error="Passwords do not match."), 400
    err = validate_password(password)
    if err:
        return jsonify(ok=False, error=err), 400

    data = file.read(Config.MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if not data:
        return jsonify(ok=False, error="The uploaded file is empty."), 400
    if len(data) > Config.MAX_UPLOAD_MB * 1024 * 1024:
        return jsonify(ok=False, error=f"File exceeds {Config.MAX_UPLOAD_MB} MB limit."), 413
    if kind == "pdf" and not data[:1024].lstrip().startswith(b"%PDF-"):
        return jsonify(ok=False, error="File is not a valid PDF."), 400

    # Convert (image / text / other) into PDF bytes in memory.
    try:
        pdf_bytes = to_pdf_bytes(kind, data, safe_name)
    except ConversionError as e:
        return jsonify(ok=False, error=str(e)), 400
    except Exception:
        return jsonify(ok=False, error="The file could not be processed."), 400
    del data

    token = secrets.token_hex(16)
    tmp_in = os.path.join(Config.UPLOAD_FOLDER, f"{secrets.token_hex(16)}.tmp")
    out_pdf, out_meta = _paths(token)

    try:
        # Unencrypted PDF lives on disk only for the duration of this request.
        fd = os.open(tmp_in, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pdf_bytes)
        del pdf_bytes

        try:
            pdf = pikepdf.open(tmp_in)
        except pikepdf.PasswordError:
            return jsonify(ok=False, error="This PDF is already password-protected. Upload an unprotected PDF."), 400
        except Exception:
            return jsonify(ok=False, error="The file is corrupted or unreadable."), 400

        with pdf:
            if pdf.is_encrypted:
                return jsonify(ok=False, error="This PDF is already encrypted."), 400
            if len(pdf.pages) == 0:
                return jsonify(ok=False, error="The PDF has no pages."), 400

            encryption = pikepdf.Encryption(
                user=password,
                owner=secrets.token_urlsafe(32),  # random owner password, never stored
                R=6,                              # AES-256 (PDF 2.0 / revision 6)
                aes=True,
                metadata=True,                    # also encrypt document metadata
                allow=pikepdf.Permissions(
                    extract=True,
                    print_lowres=True,
                    print_highres=True,
                    modify_annotation=False,
                    modify_assembly=False,
                    modify_form=False,
                    modify_other=False,
                ),
            )
            pdf.save(out_pdf, encryption=encryption)

        os.chmod(out_pdf, 0o600)
        stem = os.path.splitext(safe_name)[0] or "document"
        meta = {
            "download_name": f"{stem}_secured.pdf",
            "original_name": safe_name,
            "kind": kind,
            "kind_label": KIND_LABELS[kind],
            "size": os.path.getsize(out_pdf),
            "expires": time.time() + Config.ENCRYPTED_TTL_SECONDS,
            "owner": session["sid"],
        }
        with open(out_meta, "w", encoding="utf-8") as f:
            json.dump(meta, f)
        return jsonify(ok=True, redirect=url_for("success", token=token))
    except Exception:
        _remove_token(token)
        return jsonify(ok=False, error="Encryption failed. Please try again with a different file."), 500
    finally:
        password = confirm = None
        try:
            os.remove(tmp_in)
        except OSError:
            pass


@app.route("/success/<token>")
def success(token):
    meta = _load_meta(token)
    if not meta:
        return redirect(url_for("intro"))
    return render_template("success.html", token=token, meta=meta,
                           ttl_minutes=Config.ENCRYPTED_TTL_SECONDS // 60)


@app.route("/download/<token>")
def download(token):
    meta = _load_meta(token)
    if not meta:
        abort(404)
    pdf_path, _ = _paths(token)
    return send_file(pdf_path, mimetype="application/pdf", as_attachment=True,
                     download_name=meta["download_name"])


@app.route("/discard/<token>", methods=["POST"])
def discard(token):
    _check_csrf()
    if _load_meta(token):
        _remove_token(token)
    return jsonify(ok=True)


@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return jsonify(ok=False, error=f"File exceeds {Config.MAX_UPLOAD_MB} MB limit."), 413


@app.errorhandler(403)
def forbidden(_e):
    return jsonify(ok=False, error="Session expired. Refresh the page and try again."), 403


@app.errorhandler(404)
def not_found(_e):
    return redirect(url_for("intro"))


if __name__ == "__main__":
    # Development server. For production use: gunicorn -w 2 app:app (behind HTTPS).
    app.run(host="127.0.0.1", port=5000, debug=False)