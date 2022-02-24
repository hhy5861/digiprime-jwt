FROM kong:0.14.1-alpine
LABEL Mike Huang, hhy5861@gmail.com

ENV KONG_VERSION 0.14.1
ENV KONG_IMAGES_TAG 3.0.0
ENV KONG_PLUGINS 'bundled, digiprime-jwt'

RUN apk add --no-cache --virtual .build-deps git \
    && luarocks install --server=http://luarocks.org/manifests/hhy5861 kong-digiprime-jwt ${KONG_IMAGES_TAG} \
    && apk del .build-deps 
