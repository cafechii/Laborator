# File Upload · Scenario 29
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario29/Dockerfile -t fuellab-s29 .
#   docker run --rm -p 8080:8080 fuellab-s29
#   → http://localhost:8080/scenario29/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario29 ./Labs/scenario29
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario29/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
