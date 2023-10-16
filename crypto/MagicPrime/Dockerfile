FROM python:3.10.12-alpine

RUN apk add --no-cache socat
RUN pip install pycryptodome

WORKDIR /app
COPY src/* /app/

USER nobody
CMD ["socat", "-d", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:\"python3 server.py\",stderr"]