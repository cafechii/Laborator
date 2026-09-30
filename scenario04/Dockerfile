# File Upload · Scenario 04 — Apache runtime
# Build from lab-file-upload/:
#   docker build -f Labs/scenario04/Dockerfile -t fuellab-s04 .
#   docker run --rm -p 8080:80 fuellab-s04
FROM php:8.2-apache

WORKDIR /var/www/html

COPY Labs/menu ./menu
COPY Labs/scenario04 ./scenario04
COPY Labs/scenario04/apache.conf /etc/apache2/conf-available/file-upload-lab.conf

RUN a2enconf file-upload-lab \
    && mkdir -p /var/www/html/scenario04/uploads \
    && chown -R www-data:www-data /var/www/html/scenario04/uploads

EXPOSE 80

CMD ["apache2-foreground"]
