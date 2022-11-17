FROM ubuntu:20.04

RUN apt-get update && apt-get install -y socat

RUN useradd -ms /bin/sh out_of_cash
WORKDIR /home/out_of_cash

COPY ./out-of-cash ./
COPY ./flag.txt ./

RUN chown -R root:out_of_cash /home/out_of_cash && \
     chmod 750 /home/out_of_cash && \
     chmod 550 /home/out_of_cash/out-of-cash && \
     chown root:out_of_cash /home/out_of_cash/flag.txt && \
     chmod 440 /home/out_of_cash/flag.txt

EXPOSE 8000

CMD ["socat", "-T60", "TCP-LISTEN:8000,reuseaddr,fork,su=out_of_cash","EXEC:/home/out_of_cash/out-of-cash"]