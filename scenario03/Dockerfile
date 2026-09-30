# File Upload · Scenario 03
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario03/Dockerfile -t fuellab-s03 .
#   docker run --rm -p 8080:8080 fuellab-s03
#   → http://localhost:8080/scenario03/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario03 ./Labs/scenario03
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario03/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
