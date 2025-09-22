FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_CTYPE=C.UTF-8

RUN apt-get update 

RUN apt-get install -y \
    gcc socat curl wget locales gdb gdbserver tmux file vim python3 python3-pip ruby-full git

RUN pip3 install pwntools z3-solver angr ropper --break-system-packages

RUN gem install one_gadget seccomp-tools

RUN apt-get install -y \
    patchelf elfutils pkg-config libssl-dev liblzma-dev libcapstone4 libcapstone-dev

ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cargo install pwninit

RUN apt-get install -y \
    qemu-user qemu-user-static gdb-multiarch

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh
