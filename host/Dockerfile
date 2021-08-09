FROM ubuntu:20.04
RUN apt update  && apt upgrade -y
RUN apt install vim ssh dnsutils iputils-ping iproute2 iptables python3 -y
COPY server.py /
CMD python3 /server.py
