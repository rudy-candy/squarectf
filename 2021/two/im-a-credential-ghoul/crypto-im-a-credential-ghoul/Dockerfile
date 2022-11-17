FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y python3-pip openssh-server supervisor
RUN mkdir -p /var/run/sshd /var/log/supervisor
RUN pip3 install pycryptodome

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir /tmp/im_a_credential_ghoul
RUN mkdir -p /var/www/html
RUN mkdir -p /var/www/html/pubkeys
WORKDIR /tmp/im_a_credential_ghoul

COPY ./im_a_credential_ghoul.py .
COPY ./index.html .
COPY ./pubkeys/ /var/www/html/pubkeys
COPY ./sshd_config /etc/ssh/sshd_config

RUN python3 im_a_credential_ghoul.py

EXPOSE 22
EXPOSE 80

CMD ["/usr/bin/supervisord"]
