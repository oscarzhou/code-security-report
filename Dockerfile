FROM alpine:latest

COPY binary /
COPY templates/*.tmpl /templates/
VOLUME /data
WORKDIR /

ENTRYPOINT ["/scanreport"]