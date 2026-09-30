File Upload · Scenario 26 — Image Processor Command Injection
===============================================================

The server calls ImageMagick identify using the original filename. The Docker
image includes ImageMagick. Use the filename to append a harmless echo command.
