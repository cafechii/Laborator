File Upload · Scenario 29 — .user.ini Auto-Prepend
====================================================

Status:     ready
Category:   Server Config
Difficulty: Hard
Severity:   High
Impact:     RCE

The server uses PHP-FPM and allows .user.ini upload.
.user.ini can set auto_prepend_file to include a .jpg file as PHP.
Goal: upload .user.ini that prepends your shell, then upload the shell as .jpg.

Pattern: auto_prepend_file

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
