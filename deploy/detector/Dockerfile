FROM python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY detector /app/detector
COPY deploy/detector/entrypoint.sh /app/entrypoint.sh
RUN chmod 0555 /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
