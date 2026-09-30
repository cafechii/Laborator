# File Upload · Scenario 33
#
# build from the lab-file-upload/ folder, so both Labs/ and server/ are in the
# build context:
#   docker build -f Labs/scenario33/Dockerfile -t fuellab-s33 .
#   docker run --rm -p 8080:8080 fuellab-s33
#   → http://localhost:8080/scenario33/
FROM php:8.2-cli

WORKDIR /app

COPY Labs/menu ./Labs/menu
COPY Labs/scenario33 ./Labs/scenario33
COPY server/router.php ./router.php

RUN mkdir -p /app/Labs/scenario33/uploads

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/Labs", "/app/router.php"]
