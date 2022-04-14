FROM alpine:latest

COPY binary /
VOLUME /data
WORKDIR /

ENTRYPOINT ["/scanreport"]