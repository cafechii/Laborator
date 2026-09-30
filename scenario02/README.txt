File Upload · Scenario 02 — Client-Side Validation Bypass
=========================================================

Status:     ready
Category:   File Upload
Difficulty: Beginner
Severity:   High

Bypass file upload restrictions that are enforced only by JavaScript in
the browser.

The application uses js/checker.js to look at the selected file before the
form is submitted, and it only lets image/png through. The server does not
validate anything, so a request that never runs the script — Burp Repeater,
curl, a devtools edit — stores a file the page refuses.

Files:
  index.php       — upload bench, no server-side check
  js/checker.js   — the browser-only rule (image/png)
  uploads/        — storage for uploaded files
  Dockerfile      — docker build -t fuel-s02 . && docker run -p 8080:8080 fuel-s02

Note: uploads/ is served as data by the dev router in this scenario. The win
here is storing a disallowed file, not running code — that is scenario 1.
