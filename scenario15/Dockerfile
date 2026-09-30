# File Upload · Scenario 15 — Apache runtime
# Build from lab-file-upload/: docker build -f Labs/scenario15/Dockerfile -t fuellab-s15 .
# Run: docker run --rm -p 8080:80 fuellab-s15
FROM php:8.2-apache
WORKDIR /var/www/html
COPY Labs/menu ./menu
COPY Labs/scenario15 ./scenario15
RUN mkdir -p /var/www/html/scenario15/uploads \
    && chown -R www-data:www-data /var/www/html/scenario15/uploads
EXPOSE 80
CMD ["apache2-foreground"]
