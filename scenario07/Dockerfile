# File Upload · Scenario 07
# Build from lab-file-upload/: docker build -f Labs/scenario07/Dockerfile -t fuellab-s07 .
# Run: docker run --rm -p 8080:8080 fuellab-s07
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario07 ./Labs/scenario07
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario07/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
