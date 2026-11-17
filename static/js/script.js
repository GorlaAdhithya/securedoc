(function () {
  "use strict";

  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  /* ---------------- success page ---------------- */
  document.querySelectorAll("[data-bytes]").forEach(function (el) {
    el.textContent = fmtSize(parseInt(el.getAttribute("data-bytes"), 10) || 0);
  });
  const discardBtn = document.getElementById("discardBtn");
  if (discardBtn) {
    discardBtn.addEventListener("click", function () {
      fetch("/discard/" + discardBtn.dataset.token, { method: "POST", headers: { "X-CSRF-Token": csrf } })
        .finally(function () { window.location.href = "/"; });
    });
  }

  /* ---------------- intro page ---------------- */
  const agree = document.getElementById("agree");
  const continueBtn = document.getElementById("continueBtn");
  if (agree && continueBtn) {
    agree.addEventListener("change", function () { continueBtn.disabled = !agree.checked; });
    continueBtn.disabled = !agree.checked;
  }

  /* ---------------- index page ---------------- */
  const form = document.getElementById("encryptForm");
  if (!form) return;

  const MAX_MB = parseInt(document.body.dataset.maxMb, 10) || 20;
  const MAX_BYTES = MAX_MB * 1024 * 1024;
  const MIN_LEN = parseInt(document.body.dataset.minLen, 10) || 8;

  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const fileInfo = document.getElementById("fileInfo");
  const fileName = document.getElementById("fileName");
  const fileSize = document.getElementById("fileSize");
  const removeFile = document.getElementById("removeFile");
  const fileIcon = document.getElementById("fileIcon");
  const kindNote = document.getElementById("kindNote");
  const pw = document.getElementById("password");
  const cpw = document.getElementById("confirmPassword");
  const meterBar = document.getElementById("meterBar");
  const meterText = document.getElementById("meterText");
  const matchText = document.getElementById("matchText");
  const btn = document.getElementById("encryptBtn");
  const alertBox = document.getElementById("alertBox");
  const progressWrap = document.getElementById("progressWrap");
  const progressBar = document.getElementById("progressBar");
  const progressPct = document.getElementById("progressPct");
  const progressLabel = document.getElementById("progressLabel");

  let selectedFile = null;

  const IMG = ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"];
  const TXT = ["txt", "md", "csv", "log", "json", "xml", "ini", "yaml", "yml", "py", "js", "html", "css", "sql"];
  function kindOf(name) {
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (ext === "pdf") return { icon: "bi-file-earmark-pdf-fill", note: "PDF will be encrypted directly." };
    if (IMG.indexOf(ext) >= 0) return { icon: "bi-file-earmark-image-fill", note: "Image will be placed in a PDF and password-protected." };
    if (TXT.indexOf(ext) >= 0) return { icon: "bi-file-earmark-text-fill", note: "Text will be converted to a PDF and password-protected." };
    return { icon: "bi-file-earmark-fill", note: "File will be stored unchanged inside a password-protected PDF." };
  }

  function showAlert(msg, type) {
    alertBox.className = "alert alert-" + (type || "danger");
    alertBox.textContent = msg;
  }
  function hideAlert() { alertBox.className = "alert d-none"; }

  /* file selection */
  function setFile(file) {
    hideAlert();
    if (!file) { clearFile(); return; }
    if (file.size === 0) { clearFile(); showAlert("The selected file is empty."); return; }
    if (file.size > MAX_BYTES) { clearFile(); showAlert("File is too large. Maximum size is " + MAX_MB + " MB."); return; }
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = fmtSize(file.size);
    fileInfo.classList.remove("d-none");
    const k = kindOf(file.name);
    fileIcon.className = "bi " + k.icon;
    kindNote.textContent = k.note;
    kindNote.classList.remove("d-none");
    refresh();
  }
  function clearFile() {
    selectedFile = null;
    fileInput.value = "";
    fileInfo.classList.add("d-none");
    kindNote.classList.add("d-none");
    refresh();
  }

  dropZone.addEventListener("click", function () { fileInput.click(); });
  dropZone.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", function () { setFile(fileInput.files[0]); });
  removeFile.addEventListener("click", clearFile);
  ["dragenter", "dragover"].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.add("dragover"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.remove("dragover"); });
  });
  dropZone.addEventListener("drop", function (e) {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setFile(f);
  });

  /* show / hide password */
  document.querySelectorAll(".sd-eye").forEach(function (b) {
    b.addEventListener("click", function () {
      const input = document.getElementById(b.dataset.target);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      b.querySelector("i").className = show ? "bi bi-eye-slash" : "bi bi-eye";
    });
  });

  /* password strength */
  function passwordError(v) {
    if (v.length < MIN_LEN) return "At least " + MIN_LEN + " characters required.";
    if (v.length > 128) return "Maximum 128 characters.";
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(v); }).length;
    if (classes < 3) return "Use at least 3 of: a–z, A–Z, 0–9, symbols.";
    return null;
  }
  function score(v) {
    let s = 0;
    if (v.length >= MIN_LEN) s++;
    if (v.length >= 12) s++;
    if (v.length >= 16) s++;
    s += [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(v); }).length >= 3 ? 1 : 0;
    if (/[^A-Za-z0-9]/.test(v) && /\d/.test(v)) s++;
    return Math.min(s, 5);
  }
  const levels = [
    ["0%", "#c0392b", ""], ["20%", "#c0392b", "Very weak"], ["40%", "#e67e22", "Weak"],
    ["60%", "#d4ac0d", "Fair"], ["80%", "#1b8a4b", "Strong"], ["100%", "#146c3a", "Very strong"]
  ];

  function refresh() {
    const v = pw.value, c = cpw.value;
    const lvl = levels[v ? score(v) : 0];
    meterBar.style.width = lvl[0];
    meterBar.style.background = lvl[1];
    const err = v ? passwordError(v) : null;
    if (!v) { meterText.className = "sd-meter-text"; meterText.textContent = "Min " + MIN_LEN + " characters, with at least 3 of: a–z, A–Z, 0–9, symbols."; }
    else if (err) { meterText.className = "sd-meter-text bad"; meterText.textContent = lvl[2] + " — " + err; }
    else { meterText.className = "sd-meter-text ok"; meterText.textContent = lvl[2] + " password"; }

    if (!c) { matchText.className = "sd-meter-text"; matchText.textContent = ""; }
    else if (c === v) { matchText.className = "sd-meter-text ok"; matchText.textContent = "Passwords match"; }
    else { matchText.className = "sd-meter-text bad"; matchText.textContent = "Passwords do not match"; }

    btn.disabled = !(selectedFile && v && !err && c === v);
  }
  pw.addEventListener("input", refresh);
  cpw.addEventListener("input", refresh);

  /* submit */
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    hideAlert();
    if (btn.disabled) return;

    const fd = new FormData();
    fd.append("document", selectedFile);
    fd.append("password", pw.value);
    fd.append("confirm_password", cpw.value);

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Encrypting…';
    progressWrap.classList.remove("d-none");
    progressBar.style.width = "0%"; progressPct.textContent = "0%"; progressLabel.textContent = "Uploading…";

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/encrypt");
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.responseType = "json";

    xhr.upload.onprogress = function (ev) {
      if (!ev.lengthComputable) return;
      const pct = Math.round((ev.loaded / ev.total) * 90);
      progressBar.style.width = pct + "%"; progressPct.textContent = pct + "%";
    };
    xhr.upload.onload = function () { progressLabel.textContent = "Encrypting with AES-256…"; };

    function fail(msg) {
      progressWrap.classList.add("d-none");
      btn.innerHTML = '<i class="bi bi-lock-fill"></i> Encrypt File';
      showAlert(msg);
      refresh();
    }
    xhr.onload = function () {
      const r = xhr.response;
      if (xhr.status === 200 && r && r.ok) {
        progressBar.style.width = "100%"; progressPct.textContent = "100%"; progressLabel.textContent = "Done";
        pw.value = ""; cpw.value = "";
        window.location.href = r.redirect;
      } else {
        fail((r && r.error) || "Something went wrong. Please try again.");
      }
    };
    xhr.onerror = function () { fail("Network error. Please check your connection and try again."); };
    xhr.send(fd);
  });

  refresh();
})();
