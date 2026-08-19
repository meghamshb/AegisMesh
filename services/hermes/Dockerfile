FROM alpine:3.20

RUN apk add --no-cache curl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV HTTP_PROXY=http://policy-gateway:8080 \
    HTTPS_PROXY=http://policy-gateway:8080 \
    NO_PROXY=localhost,127.0.0.1,policy-gateway,postgres

ENTRYPOINT ["/entrypoint.sh"]
