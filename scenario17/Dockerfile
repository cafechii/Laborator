# File Upload · Scenario 17
# Build from lab-file-upload/: docker build -f Labs/scenario17/Dockerfile -t fuellab-s17 .
# Run: docker run --rm -p 8080:8080 fuellab-s17
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario17 ./Labs/scenario17
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario17/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
