FROM alpine:latest

WORKDIR /app
COPY dist .
COPY templates/*.tmpl ./templates/
VOLUME /data

ENTRYPOINT ["/app/code-security-report"]