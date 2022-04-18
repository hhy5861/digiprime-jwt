FROM kong:2.8.1-ubuntu
LABEL Mike Huang, hhy5861@gmail.com

ENV KONG_PLUGINS_TAG 0.0.9
ENV KONG_PLUGINS 'bundled, digiprime-jwt'

USER root

RUN apt-get update -y && apt-get install git make cmake build-essential -y \
    && luarocks install --server=http://luarocks.org/manifests/hhy5861 digiprime-jwt ${KONG_PLUGINS_TAG} \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
