File Upload · Scenario 32 — SSI Injection via .shtml
======================================================

Status:     ready
Category:   SSI
Difficulty: Medium
Severity:   High
Impact:     RCE

The server allows .shtml files which support Server Side Includes.
SSI directive <!--#exec cmd="id" --> can execute commands.
Goal: upload .shtml file with SSI exec payload.

Pattern: .shtml SSI exec

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
