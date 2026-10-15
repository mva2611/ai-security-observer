FROM netsampler/goflow2@sha256:b930e69d1bc7bd765da5b45d12f04edd10970c310b33ba44fd12a07a870da8e6 AS goflow2

FROM python:3.13-alpine

WORKDIR /app

COPY --from=goflow2 /goflow2 /usr/local/bin/goflow2
COPY goflow2-mapping.yaml /app/goflow2-mapping.yaml
COPY flowstore.py /app/flowstore.py
COPY schema.sql /app/schema.sql
COPY migrate_flowstore_nat.py /app/migrate_flowstore_nat.py
COPY entrypoint.sh /app/entrypoint.sh

RUN addgroup -S collector \
    && adduser -S -G collector collector \
    && chmod +x /app/entrypoint.sh

USER collector

ENTRYPOINT ["/app/entrypoint.sh"]
