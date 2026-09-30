# File Upload · Scenario 20
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario20/Dockerfile -t fuellab-s20 .
#   docker run --rm -p 8080:8080 fuellab-s20
#   → http://localhost:8080/scenario20/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario20 ./Labs/scenario20
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario20/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
