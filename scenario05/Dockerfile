# File Upload · Scenario 05 — Apache runtime
# Build from lab-file-upload/:
#   docker build -f Labs/scenario05/Dockerfile -t fuellab-s05 .
#   docker run --rm -p 8080:80 fuellab-s05
FROM php:8.2-apache

WORKDIR /var/www/html

COPY Labs/menu ./menu
COPY Labs/scenario05 ./scenario05
COPY Labs/scenario05/apache.conf /etc/apache2/conf-available/file-upload-lab.conf

RUN a2enconf file-upload-lab \
    && mkdir -p /var/www/html/scenario05/uploads \
    && chown -R www-data:www-data /var/www/html/scenario05/uploads

EXPOSE 80

CMD ["apache2-foreground"]
