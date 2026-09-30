File Upload · Scenario 05 — Case-Sensitive Extension Check
=============================================================

Status:     ready
Category:   File Upload
Difficulty: Easy
Severity:   Medium
Impact:     RCE

Slip past an extension check that only looks at one capitalisation.

This lab demonstrates a case-sensitive comparison.

The handler compares the extension with the string php. exploit.pHp is not
equal to it, so the file is stored, while the web server still hands it to the
PHP interpreter.

Alternative endings such as .phtml are not executed in this scenario, so the
case of the letters is the only way in.

Your goal is to store PHP code whose ending merely looks different.

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build -t fuel-s05 . && docker run -p 8080:80 fuel-s05

Runtime: Apache (`apache.conf`) is required for the final step.
