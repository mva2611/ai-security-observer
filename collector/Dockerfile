FROM python:3.13-alpine

WORKDIR /app

COPY flowstore.py /app/flowstore.py
COPY schema.sql /app/schema.sql

RUN addgroup -S collector \
    && adduser -S -G collector collector

USER collector

ENTRYPOINT ["python3", "/app/flowstore.py"]
