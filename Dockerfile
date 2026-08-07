FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_CTYPE=C.UTF-8

ENV PATH="/root/.gef/.venv-gef/bin:${PATH}"
RUN apt-get update && apt-get install -y wget
RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh
RUN echo ". /root/.gef/.venv-gef/bin/activate" >> /root/.bashrc

ENV PATH="/root/.local/bin:${PATH}"
RUN apt-get install -y pkg-config cmake build-essential
RUN uv pip install pwntools

RUN apt-get install -y qemu-user qemu-system

ENV PATH="/root/.cargo/bin:${PATH}"
RUN apt-get install -y curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN apt-get install -y patchelf libssl-dev liblzma-dev
RUN cargo install pwninit

RUN rm -rf /var/lib/apt/lists/*
