# File Upload · Scenario 18 — Apache runtime
# Build from lab-file-upload/:
#   docker build -f Labs/scenario18/Dockerfile -t fuellab-s18 .
#   docker run --rm -p 8080:80 fuellab-s18
FROM php:8.2-apache

WORKDIR /var/www/html

COPY Labs/menu ./menu
COPY Labs/scenario18 ./scenario18
COPY Labs/scenario18/apache.conf /etc/apache2/conf-available/file-upload-lab.conf

RUN a2enconf file-upload-lab \
    && mkdir -p /var/www/html/scenario18/uploads \
    && chown -R www-data:www-data /var/www/html/scenario18/uploads

EXPOSE 80

CMD ["apache2-foreground"]
