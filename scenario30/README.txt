File Upload · Scenario 30 — Trailing Dot/Space Bypass
=======================================================

Status:     ready
Category:   Filter Bypass
Difficulty: Medium
Severity:   High
Impact:     RCE

The server blocks .php but does not trim trailing dots and spaces.
On Windows, filesystem strips trailing dots/spaces and saves as .php.
Goal: upload shell.php. or shell.php  to bypass filter and get RCE.

Pattern: shell.php. / shell.php<space>

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
