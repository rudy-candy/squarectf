FROM ubuntu:20.04
MAINTAINER kfoxsq

RUN apt-get update && apt-get install -y socat

RUN useradd -ms /bin/sh itsjustanxor
WORKDIR /home/itsjustanxor

COPY ./itsjustanxor ./
COPY ./flag.txt ./

RUN chown -R root:itsjustanxor /home/itsjustanxor && \
     chmod 750 /home/itsjustanxor && \
     chmod 550 /home/itsjustanxor/itsjustanxor && \
     chown root:itsjustanxor /home/itsjustanxor/flag.txt && \
     chmod 440 /home/itsjustanxor/flag.txt

EXPOSE 8000

CMD ["socat", "-T60", "TCP-LISTEN:8000,reuseaddr,fork,su=itsjustanxor","EXEC:/home/itsjustanxor/itsjustanxor,pty,ctty,echo=0"]