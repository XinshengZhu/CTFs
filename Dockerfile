FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_CTYPE=C.UTF-8

RUN apt-get update && \
    apt-get install -y \
        gcc \
        cmake \
        locales \
        socat \
        curl \
        wget \
        gdb \
        gdbserver \
        gdb-multiarch \
        tmux \
        vim \
        file \
        python3 \
        python3-pip \
        ruby-full \
        git \
        patchelf \
        elfutils \
        libssl-dev \
        liblzma-dev \
        libcapstone-dev \
        qemu-user-binfmt \
        pkg-config \
        linux-tools-common && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools z3-solver ropper angr --break-system-packages

RUN gem install one_gadget seccomp-tools

ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cargo install pwninit

RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh
