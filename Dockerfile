FROM kong:2.7.1-alpine
LABEL Mike Huang, hhy5861@gmail.com

ENV KONG_IMAGES_TAG 0.0.1
ENV KONG_PLUGINS 'bundled, digiprime-jwt'

USER root

RUN apk add --no-cache --virtual .build-deps git \
    && luarocks install --server=http://luarocks.org/manifests/hhy5861 digiprime-jwt ${KONG_IMAGES_TAG} \
    && apk del .build-deps 
