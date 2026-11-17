"""Turn an uploaded file into a PDF so it can get native PDF password protection.

- PDF            -> used as is
- Image          -> one A4 page with the image fitted on it
- Text           -> paginated monospace text
- Anything else  -> cover page + the original file embedded byte-for-byte
                    (open the PDF, enter the password, then save the attachment)
"""
import io
import mimetypes

import pikepdf
from PIL import Image, ImageOps
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from config import Config

Image.MAX_IMAGE_PIXELS = Config.MAX_IMAGE_PIXELS

IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"}
TEXT_EXTS = {"txt", "md", "csv", "log", "json", "xml", "ini", "yaml", "yml", "py", "js", "html", "css", "sql"}

PAGE_W, PAGE_H = A4
MARGIN = 40


class ConversionError(Exception):
    """Raised with a message that is safe to show to the user."""


def kind_for(ext):
    ext = ext.lower().lstrip(".")
    if ext == "pdf":
        return "pdf"
    if ext in IMAGE_EXTS:
        return "image"
    if ext in TEXT_EXTS:
        return "text"
    return "file"


def image_to_pdf(data):
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        raise ConversionError("The image is corrupted or not a supported image.")
    img = ImageOps.exif_transpose(img)
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA")
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[-1])
        img = bg
    elif img.mode != "RGB":
        img = img.convert("RGB")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    avail_w, avail_h = PAGE_W - 2 * 30, PAGE_H - 2 * 30
    iw, ih = img.size
    scale = min(avail_w / iw, avail_h / ih, 1.0 if max(iw, ih) < 600 else 99)
    w, h = iw * scale, ih * scale
    c.drawImage(ImageReader(img), (PAGE_W - w) / 2, (PAGE_H - h) / 2, w, h)
    c.showPage()
    c.save()
    return buf.getvalue()


def text_to_pdf(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    if len(text) > Config.MAX_TEXT_CHARS:
        raise ConversionError("Text file is too long to convert.")
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    # Built-in PDF fonts only cover Latin-1; replace the rest.
    text = "".join(ch if (ch == "\n" or 32 <= ord(ch) < 256) else "?" for ch in text)

    font, size, lead = "Courier", 10, 13
    max_w = PAGE_W - 2 * MARGIN
    lines = []
    for raw in text.split("\n"):
        line = raw
        if not line:
            lines.append("")
            continue
        while stringWidth(line, font, size) > max_w:
            cut = len(line)
            while cut > 1 and stringWidth(line[:cut], font, size) > max_w:
                cut -= 1
            lines.append(line[:cut])
            line = line[cut:]
        lines.append(line)

    per_page = int((PAGE_H - 2 * MARGIN) // lead)
    if (len(lines) + per_page - 1) // per_page > Config.MAX_TEXT_PAGES:
        raise ConversionError("Text file is too long to convert.")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for start in range(0, max(len(lines), 1), per_page):
        t = c.beginText(MARGIN, PAGE_H - MARGIN - size)
        t.setFont(font, size, lead)
        for ln in lines[start:start + per_page]:
            t.textLine(ln)
        c.drawText(t)
        c.showPage()
    c.save()
    return buf.getvalue()


def _cover_page(filename, size):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFillColorRGB(0.106, 0.541, 0.294)
    c.rect(0, PAGE_H - 110, PAGE_W, 110, stroke=0, fill=1)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(50, PAGE_H - 65, "SecureDoc")
    c.setFont("Helvetica", 12)
    c.drawString(50, PAGE_H - 88, "Password-protected file container")
    c.setFillColorRGB(0.09, 0.19, 0.12)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, PAGE_H - 170, "This PDF contains an encrypted file")
    c.setFont("Helvetica", 12)
    safe = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in filename)
    kb = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.2f} MB"
    c.drawString(50, PAGE_H - 200, f"File name: {safe}")
    c.drawString(50, PAGE_H - 218, f"File size: {kb}")
    c.drawString(50, PAGE_H - 255, "How to get your file:")
    steps = [
        "1. Open the Attachments panel (paper-clip icon) in your PDF reader.",
        "2. Right-click / tap the file and choose Save or Save Attachment.",
        "Adobe Acrobat Reader and most desktop viewers support this.",
    ]
    for i, s in enumerate(steps):
        c.drawString(60, PAGE_H - 280 - i * 20, s)
    c.showPage()
    c.save()
    return buf.getvalue()


def file_to_pdf(data, filename):
    cover = _cover_page(filename, len(data))
    pdf = pikepdf.open(io.BytesIO(cover))
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    pdf.attachments[filename] = pikepdf.AttachedFileSpec(
        pdf, data, description="Original file protected by SecureDoc", mime_type=mime)
    pdf.Root.PageMode = pikepdf.Name.UseAttachments  # Acrobat opens the attachments panel
    out = io.BytesIO()
    pdf.save(out)
    pdf.close()
    return out.getvalue()


def to_pdf_bytes(kind, data, filename):
    if kind == "pdf":
        return data
    if kind == "image":
        return image_to_pdf(data)
    if kind == "text":
        return text_to_pdf(data)
    return file_to_pdf(data, filename)