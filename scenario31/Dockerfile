# File Upload · Scenario 31
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario31/Dockerfile -t fuellab-s31 .
#   docker run --rm -p 8080:8080 fuellab-s31
#   → http://localhost:8080/scenario31/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario31 ./Labs/scenario31
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario31/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
