FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
&& apt-get install snort -y
RUN apt-get clean
RUN apt install net-tools iproute2 iputils-ping traceroute -y
RUN apt install procps -y
RUN apt install python3 -y
COPY snort.conf /etc/snort/
#COPY local.rules /etc/snort/rules
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY pigrelay.py /
COPY entrypoint.sh /
CMD sh entrypoint.sh
