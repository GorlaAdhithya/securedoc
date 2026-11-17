# 🔐 SecureDoc – Password Protected File Encryption

SecureDoc is a secure document protection application built using Python and Flask. It allows users to protect sensitive files with password-based PDF encryption using AES-256 security.

Upload a document, set a password, and download a protected PDF that prompts for a password when opened in a compatible PDF reader.

## 🚀 Features

- Password-protected PDF encryption.
- AES-256 encryption using PDF revision 6.
- PDF file encryption.
- Image support (PNG, JPG, GIF, BMP, WEBP, TIFF).
- Text file support (TXT, MD, CSV, LOG, JSON).
- Other file formats supported through PDF attachments.
- User-friendly web interface.
- Temporary file cleanup.
- Session-based download protection.

## 🔐 How Encryption Works

SecureDoc uses the standard PDF Security Handler through pikepdf (qpdf).

- AES-256 encryption.
- PDF revision 6 (R=6).
- User-defined password.
- Randomly generated owner password.
- Encrypted document metadata.
- Password protection built into the PDF itself.

## 📂 Supported Files

| File type | Output |
|---|---|
| PDF | Encrypted PDF |
| PNG, JPG, GIF, BMP, WEBP, TIFF | Image converted into PDF and encrypted |
| TXT, MD, CSV, JSON, LOG | Text converted into PDF and encrypted |
| DOCX, ZIP, XLSX and others | Original file embedded as a PDF attachment and encrypted |

## 🔄 Application Workflow

1. Open the SecureDoc website.
2. Accept the Terms and Conditions.
3. Upload a document.
4. Enter a password.
5. Generate the encrypted PDF.
6. Download the protected document.
7. Enter the password in a compatible PDF reader.

## 🛠️ Technologies Used

- Python
- Flask
- HTML5
- CSS3
- JavaScript
- pikepdf
- qpdf
- Git and GitHub

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/GorlaAdhithya/securedoc.git
cd securedoc
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

### 6. Open in your browser

http://127.0.0.1:5000

## 🛡️ Security Considerations

- Passwords should never be stored in plain text.
- Validate uploaded file types and sizes.
- Use secure temporary file handling.
- Protect downloads using session authorization.
- Configure HTTPS and a strong secret key in production.
- Never commit passwords, private documents, or secret keys to GitHub.

## 📁 Project Structure

```text
SecureDoc/
│
├── app.py
├── config.py
├── converters.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── intro.html
│   ├── index.html
│   └── success.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── img/
│
├── uploads/
└── encrypted/
```

## 🔮 Future Enhancements

- Cloud deployment.
- Multiple document encryption.
- Improved file format support.
- Enhanced security monitoring.
- User authentication.

## 👨‍💻 Developer

**Adhithya Gorla**

GitHub: https://github.com/GorlaAdhithya

## 📜 License

Educational project. Add a license file if you intend to distribute the project under an open-source license.