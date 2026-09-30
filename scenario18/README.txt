File Upload · Scenario 18 — Server Config Upload (.htaccess)
===============================================================

Status:     ready
Category:   File Upload
Difficulty: Hard
Severity:   High
Impact:     RCE

Let the server learn a new executable ending from a configuration file you
uploaded.

This lab demonstrates an unrestricted upload of an Apache configuration file.

The handler blocks names ending in .php, which stops every payload with a
known ending. It says nothing about .htaccess, and that file can change the
rules of the folder it is stored in.

One line inside it is enough to declare an ending executable.

Your goal is to store .htaccess in uploads/, then store a file using the
ending it introduces.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s07 . && docker run -p 8080:80 fuel-s07

Runtime: Apache (`apache.conf`) is required for the final step.
