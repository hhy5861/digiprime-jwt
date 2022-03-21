FROM kong:2.8.0-alpine
LABEL Mike Huang, hhy5861@gmail.com

ENV KONG_PLUGINS_TAG 0.0.7
ENV KONG_PLUGINS 'bundled, digiprime-jwt'

USER root

RUN apk add --no-cache --virtual .build-deps git make cmake build-base \
    && luarocks install --server=http://luarocks.org/manifests/hhy5861 digiprime-jwt ${KONG_PLUGINS_TAG} \
    && apk del .build-deps 
