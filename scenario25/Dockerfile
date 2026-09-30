# File Upload · Scenario 25
# Build from lab-file-upload/: docker build -f Labs/scenario25/Dockerfile -t fuellab-s25 .
# Run: docker run --rm -p 8080:8080 fuellab-s25
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario25 ./Labs/scenario25
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario25/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
