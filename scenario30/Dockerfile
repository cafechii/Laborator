# File Upload · Scenario 30
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario30/Dockerfile -t fuellab-s30 .
#   docker run --rm -p 8080:8080 fuellab-s30
#   → http://localhost:8080/scenario30/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario30 ./Labs/scenario30
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario30/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
