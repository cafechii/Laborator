# File Upload · Scenario 27
# Build from lab-file-upload/: docker build -f Labs/scenario27/Dockerfile -t fuellab-s27 .
# Run: docker run --rm -p 8080:8080 fuellab-s27
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario27 ./Labs/scenario27
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario27/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
