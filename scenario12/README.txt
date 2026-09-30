File Upload · Scenario 12 — SVG Stored XSS
============================================

The application stores SVG without sanitizing active content and serves it
from the upload origin. Upload a harmless SVG event-handler payload and open it.
