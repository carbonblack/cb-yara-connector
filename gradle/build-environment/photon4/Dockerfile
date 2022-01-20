# This dockerfile creates the cb enterprise build environment
ARG ARTIFACTORY_SERVER=artifactory-pub.bit9.local
ARG ARTIFACTORY_BASE_IMAGE=${ARTIFACTORY_SERVER}:5000/cb/connector_env_base:photon4-1.4.0
#ARG BASE_IMAGE=photon4builder:latest
ARG BASE_IMAGE=${BASE_IMAGE:-$ARTIFACTORY_BASE_IMAGE}

FROM ${BASE_IMAGE}

ARG ARTIFACTORY_SERVER
ENV ARTIFACTORY_SERVER=${ARTIFACTORY_SERVER}

ARG BASE_IMAGE
ENV BASE_IMAGE=${BASE_IMAGE}

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

#install libyara 3.11
RUN curl -o libyara.tar.gz -fSL https://github.com/VirusTotal/yara/archive/refs/tags/v3.11.0.tar.gz && tar -zxf libyara.tar.gz && cd yara-3.11.0 && ./bootstrap.sh && ./configure || cat config.log && make && make install

ENTRYPOINT ["/entrypoint.sh"]
