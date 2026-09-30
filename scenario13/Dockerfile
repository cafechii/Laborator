# File Upload · Scenario 13
# Build from lab-file-upload/: docker build -f Labs/scenario13/Dockerfile -t fuellab-s13 .
# Run: docker run --rm -p 8080:8080 fuellab-s13
FROM php:8.2-cli

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario13 ./Labs/scenario13
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario13/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
