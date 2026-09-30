File Upload · Scenario 04 — Extension Blacklist Bypass
=========================================================

Status:     ready
Category:   File Upload
Difficulty: Easy
Severity:   High
Impact:     RCE

Upload a PHP script with a file ending that is not on the block list.

This lab demonstrates a server-side extension blacklist.

The handler reads the extension of the uploaded file, compares it with a short
list and rejects .php. Nothing else is looked at.

A blacklist only contains what its author thought of, so anything else gets
in.

Your goal is to store a PHP file the list does not know and have the server
run it.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s04 . && docker run -p 8080:80 fuel-s04

Runtime: Apache (`apache.conf`) is required for the final step.
