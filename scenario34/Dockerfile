# File Upload · Scenario 34
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario34/Dockerfile -t fuellab-s34 .
#   docker run --rm -p 8080:8080 fuellab-s34
#   → http://localhost:8080/scenario34/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario34 ./Labs/scenario34
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario34/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
