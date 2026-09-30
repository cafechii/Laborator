File Upload · Scenario 19 — Nested Extension Stripping
=========================================================

Status:     ready
Category:   File Upload
Difficulty: Hard
Severity:   High
Impact:     RCE

Build a file name that still ends in .php after the sanitizer has removed .php
from it.

This lab demonstrates a non-recursive sanitization flaw.

The handler does not reject the name, it rewrites it: .php is replaced with
nothing. On exploit.p.phphp that leaves exploit.php.

The check is happy because the stored name looks clean, and the substitution
is exactly what makes it dirty again.

Your goal is to end up with a stored file the server runs as PHP.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s08 . && docker run -p 8080:8080 fuel-s08
