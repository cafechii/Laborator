# File Upload · Scenario 16
# Build from lab-file-upload/: docker build -f Labs/scenario16/Dockerfile -t fuellab-s16 .
# Run: docker run --rm -p 8080:8080 fuellab-s16
FROM php:8.2-cli
RUN docker-php-ext-install dom

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario16 ./Labs/scenario16
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario16/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
