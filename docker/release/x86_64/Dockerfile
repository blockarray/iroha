FROM ubuntu:16.04

ARG iroha-deb-path=iroha.deb

RUN apt-get update;\
    apt-get upgrade; \
    apt-get install -y \
    libc-ares-dev

#Install iroha
COPY ${iroha-deb-path} /tmp/iroha.deb
RUN dpkg -i /tmp/iroha.deb; rm -f /tmp/iroha.deb

WORKDIR /opt/iroha_data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sbin/init"]