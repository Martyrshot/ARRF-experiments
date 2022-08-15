FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=nointeractive
ARG LISTENIP

# Set up OQS and bind
RUN apt update -y
RUN apt upgrade -y
RUN apt update -y
RUN TZ="Canada/Toronto" apt install ssh vim git pkg-config autoconf automake build-essential libnghttp2-dev libtool libtool-bin libuv1-dev libcap-dev libssl-dev iproute2 -y
RUN TZ="Canada/Toronto" apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz -y
RUN git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/Martyrshot/openssl.git /oqs-openssl-source
RUN git clone https://github.com/open-quantum-safe/liboqs.git
RUN cd liboqs && git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
RUN mkdir liboqs/build
RUN cd liboqs/build && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/oqs-openssl-source/oqs ..
RUN cd liboqs/build && ninja
RUN cd liboqs/build && ninja install
RUN cd oqs-openssl-source && ./Configure no-shared linux-x86_64 --prefix=/oqs-openssl -lm
RUN cd oqs-openssl-source && make
RUN cd oqs-openssl-source && make install
RUN git clone --branch even-larger-udp https://github.com/Martyrshot/OQS-bind.git /bind9
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN cd bind9/ && autoreconf -fi
RUN cd bind9/ && ./configure CFLAGS="-Wl,--no-as-needed" LIBS="-loqs -ldl" CPPFLAGS="-I/oqs-openssl-source/oqs/include" LDFLAGS="-L/oqs-openssl/lib -L/oqs-openssl-source/oqs/lib" --with-openssl=/oqs-openssl;
RUN cd bind9/ && make
RUN cd bind9/ && make install
RUN mkdir /usr/local/etc/bind
RUN mkdir /usr/local/etc/bind/zones
RUN mkdir /var/cache/bind
COPY named.conf /usr/local/etc
RUN mkdir /setup_files
COPY add_ds.bash /setup_files/
COPY move_ds.bash /setup_files/

# Setting up daemon
RUN apt update
RUN apt install iptables iputils-ping iperf gcc make net-tools iproute2 libnetfilter-queue-dev netcat traceroute vim -y
RUN apt install git libtool libnl-3-dev libnl-genl-3-dev binutils-dev libreadline6-dev autoconf libpcap-dev -y

COPY ./rrfrag/src /rrfrag/src
COPY ./rrfrag/include /rrfrag/include
COPY ./rrfrag/c-hashmap /rrfrag/c-hashmap
COPY ./rrfrag/makefile /rrfrag/makefile
WORKDIR /rrfrag
RUN make daemon
ENV LISTENIP=${LISTENIP}
WORKDIR /
#CMD bash -c 'iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && ./daemon ${LISTENIP} &'


#COPY db.goertzen /usr/local/etc/bind/zones
#RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a RSASHA256 -b 1024 -n ZONE goertzen
#RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a RSASHA256 -b 1024 -n ZONE -f KSK goertzen
#RUN cd /usr/local/etc/bind/zones && dnssec-signzone -o goertzen -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.goertzen
#CMD /bin/bash # arguments will need to be hard coded with the parse script here
COPY db.goertzen /usr/local/etc/bind/zones
RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a DILITHIUM2 -n ZONE goertzen
RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a DILITHIUM2 -n ZONE -f KSK goertzen
RUN cd /usr/local/etc/bind/ && rndc-confgen -a > rndc.key
ARG SIGN=unknown
RUN echo $SIGN
RUN cd /usr/local/etc/bind/zones && dnssec-signzone -o goertzen -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.goertzen
CMD /setup_files/move_ds.bash goertzen. && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && cd / && ./rrfrag/daemon ${LISTENIP} --maxudp 256 & named -d 3 && /bin/bash
