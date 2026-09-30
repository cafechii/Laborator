File Upload · Scenario 33 — SVG SSRF via xlink
================================================

Status:     ready
Category:   SVG SSRF
Difficulty: Medium
Severity:   Medium
Impact:     SSRF/LFI

The server allows SVG upload and renders it.
SVG <image> tag with xlink:href can trigger SSRF to internal services.
Goal: upload SVG that fetches internal URL like http://127.0.0.1/ or http://169.254.169.254/

Pattern: xlink:href="http://..."

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
