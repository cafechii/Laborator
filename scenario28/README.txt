File Upload · Scenario 28 — IIS web.config Override
=====================================================

Status:     ready
Category:   Server Config
Difficulty: Hard
Severity:   High
Impact:     RCE

The server blocks .php but allows web.config on IIS.
A web.config file can map a custom extension like .jpg to execute as PHP/ASP.
Goal: upload web.config that enables .jpg execution, then upload a web shell as .jpg.

Pattern: web.config handler mapping

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
