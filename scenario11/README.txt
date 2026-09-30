File Upload · Scenario 11 — PUT Method Upload
================================================

Status:     ready
Category:   File Upload
Difficulty: Medium
Severity:   High
Impact:     RCE

Store a file by sending a PUT request instead of a multipart form.

This lab demonstrates an upload endpoint built on the PUT method. The page
only provides a normal multipart request to start from; the intended work is
manual in Burp.

Change the method to PUT, remove the multipart body, place the raw file bytes
in the body, and add the X-Filename header. The endpoint writes that body as
the file content. There is no server-side file-type check.

Your goal is to put a PHP file into uploads/ with PUT and open it.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s15 . && docker run -p 8080:8080 fuel-s15
