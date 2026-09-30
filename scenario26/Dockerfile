# File Upload · Scenario 26
# Build from lab-file-upload/: docker build -f Labs/scenario26/Dockerfile -t fuellab-s26 .
# Run: docker run --rm -p 8080:8080 fuellab-s26
FROM php:8.2-cli
RUN apt-get update \
    && apt-get install -y --no-install-recommends imagemagick \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario26 ./Labs/scenario26
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario26/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
