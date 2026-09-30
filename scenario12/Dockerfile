# File Upload · Scenario 12
# Build from lab-file-upload/: docker build -f Labs/scenario12/Dockerfile -t fuellab-s12 .
# Run: docker run --rm -p 8080:8080 fuellab-s12
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario12 ./Labs/scenario12
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario12/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
