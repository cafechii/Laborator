File Upload · Scenario 03 — MIME Type Validation Bypass
========================================================

Status:     ready
Category:   File Upload
Difficulty: Easy
Severity:   High

Bypass weak server-side MIME type validation by changing the uploaded file's
Content-Type header.

The handler compares $_FILES['fileToUpload']['type'] with image/jpeg,
image/png and image/gif. That value is written by the client into the
multipart body and is never checked against the real bytes, so declaring an
allowed image type is enough to land proof.php.

Files:
  index.php   — upload bench (trusts the declared type)
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s03 . && docker run -p 8080:8080 fuel-s03

The dev router lets uploads/ execute PHP in this scenario (scenario 1 and 3),
because code execution is the intended outcome.
