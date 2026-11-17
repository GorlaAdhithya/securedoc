# SecureDoc – Password Protected File Encryption

Accept the terms on the intro page, then upload a **PDF, image (PNG/JPG/...), text file or any other file**, set a password, download a PDF that asks for the password in **any** PDF reader
(Adobe Acrobat, Chrome, Android / iOS viewers) with the native *"Enter password to open file"* dialog —
the same experience as a password-protected e-Aadhaar PDF.

## How the encryption works (e-Aadhaar style)

e-Aadhaar PDFs use the standard **PDF Security Handler**: the password is embedded in the PDF's
encryption dictionary, so every compliant reader prompts for it. SecureDoc uses the same mechanism,
with a stronger cipher:

- `pikepdf` (qpdf) with **AES-256, PDF revision 6** (`R=6`, `aes=True`)
- User password = the password you choose; a random owner password is generated and discarded
- Document metadata is encrypted too
- No website-side password check — the protection lives inside the file

## Supported files

| Upload | What you get |
|---|---|
| PDF | The same PDF, encrypted |
| PNG, JPG, GIF, BMP, WEBP, TIFF | Image placed on an A4 PDF page, encrypted |
| TXT, MD, CSV, LOG, JSON, ... | Text rendered into a PDF, encrypted |
| Anything else (DOCX, ZIP, XLSX, ...) | Cover page + your original file embedded unchanged in an encrypted PDF. Unlock it, open the Attachments panel and save the file |

## Flow

Intro page (`/`) with Terms & Conditions -> tick "I agree" -> Agree & Continue -> upload page (`/app`) -> success / download.

## Run it

```bash
cd SecureDoc
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                     # open http://127.0.0.1:5000
```

Production: `SECRET_KEY=<long random> SESSION_COOKIE_SECURE=1 gunicorn -w 2 app:app` behind HTTPS.
(Rate limiting is in-memory per worker; encrypted downloads are tied to the browser session via a cookie.)

## Security notes

- Passwords are never stored or logged; the random owner password is never stored
- Uploads: extension + MIME + `%PDF-` magic bytes + size (20 MB) + parse check; encrypted/corrupt PDFs rejected
- Unencrypted upload is written with a random name (mode 0600) and deleted in a `finally` block
- Encrypted files are stored under random 128-bit tokens, only downloadable by the creating session,
  and auto-deleted after 15 minutes (or via "Delete now")
- CSRF token, strict security headers, no path input from users (`secure_filename`, token regex)

## Configure

Edit `config.py` (upload size, TTL, password policy, rate limit).

## Optional: MySQL

Not needed for v1. Add it later for audit logs (never store passwords or file contents).

## Structure

```
SecureDoc/
  app.py  converters.py  config.py  requirements.txt  README.md
  templates/  intro.html  index.html  success.html
  static/css/style.css  static/js/script.js  static/img/logo.svg
  uploads/  encrypted/
```