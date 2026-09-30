# File Upload · Scenario 14
# Build from lab-file-upload/: docker build -f Labs/scenario14/Dockerfile -t fuellab-s14 .
# Run: docker run --rm -p 8080:8080 fuellab-s14
FROM php:8.2-cli
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzip-dev \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Labs/menu ./Labs/menu
COPY Labs/scenario14 ./Labs/scenario14
COPY server/router.php ./router.php
RUN mkdir -p /app/Labs/scenario14/uploads
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
