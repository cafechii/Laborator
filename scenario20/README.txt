File Upload · Scenario 20 — Magic Byte Spoofing
==================================================

Status:     ready
Category:   File Upload
Difficulty: Hard
Severity:   High
Impact:     RCE

Let a PHP file pass as a GIF by borrowing the signature of a GIF.

This lab demonstrates a magic byte check done with PHP fileinfo.

The handler opens the file, asks what its first bytes describe and accepts
image/gif. What follows is never examined.

A file type is only a handful of bytes at the start of a file, and bytes can
be copied.

Your goal is to store a file the checker calls a picture and the server runs
as PHP.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s09 . && docker run -p 8080:8080 fuel-s09
