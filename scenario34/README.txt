File Upload · Scenario 34 — ffmpeg HLS SSRF / File Read
=========================================================

Status:     ready
Category:   Audio/Video
Difficulty: Hard
Severity:   High
Impact:     RCE

The server uses ffmpeg to process uploaded audio/video.
ffmpeg HLS playlist (m3u8) can reference local files or internal URLs.
Goal: upload malicious m3u8 or avi containing HLS that reads /etc/passwd or SSRFs.

Pattern: HLS playlist file:///etc/passwd

Files:
  index.php   — upload bench
  uploads/    — storage for uploaded files
  Dockerfile  — docker build
