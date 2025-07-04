FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_CTYPE=C.UTF-8

RUN apt-get update && \
    apt-get install -y \
    gcc socat python3 curl wget locales gdb gdbserver python3-pip tmux ruby-full file vim \
    patchelf elfutils pkg-config libssl-dev liblzma-dev libcapstone4 libcapstone-dev

RUN pip3 install pwntools z3-solver angr ropper --break-system-packages

RUN gem install one_gadget seccomp-tools

RUN bash -c "$(wget https://gef.blah.cat/sh -O -)"

ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cargo install pwninit
