FROM phusion/baseimage:latest
MAINTAINER matrixme <matrixme@live.cn>

RUN dpkg --add-architecture i386 && \
	apt-get remove -y vim-tiny && \
	apt-get -y update && \
	apt install -y \
	vim \
	libc6:i386 \
	libc6-dbg:i386 \
	libc6-dbg \
	lib32stdc++6 \
	g++-multilib \
	net-tools  \
	libffi-dev \
	libssl-dev \
	python \
	python-pip \
	python-capstone \
	tmux \
	strace \
	ltrace \
	git \
	wget \
	gdb --fix-missing 
	
RUN apt-get -y autoremove
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip install \
	ropgadget \
	pwntools \
	zio && \
	rm -rf ~/.cache/pip/*

RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
RUN sed -i "s/sudo//g" opt/pwndbg/setup.sh
RUN cd /opt/pwndbg && \
	./setup.sh 

RUN git clone https://github.com/niklasb/libc-database /opt/libc-database

RUN mkdir -p /CTF/game && \
	wget https://raw.githubusercontent.com/inaz2/roputils/master/roputils.py -O /CTF/roputils.py

WORKDIR /CTF/game

ENTRYPOINT ["/bin/bash"]