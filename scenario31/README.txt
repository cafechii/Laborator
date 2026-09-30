File Upload · Scenario 31 — IIS Semicolon Bypass
==================================================

Status:     ready
Category:   IIS Bypass
Difficulty: Medium
Severity:   High
Impact:     RCE

IIS 6 executes file as ASP if semicolon present: shell.asp;.jpg is treated as .asp.
The server checks extension after last dot (.jpg) and allows it.
Goal: upload shell.asp;.jpg containing ASP/PHP shell.

Pattern: shell.asp;.jpg

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
