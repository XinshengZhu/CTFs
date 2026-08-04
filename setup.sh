#!/bin/bash

sudo su

apt-get update
wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh
echo ". /root/.gef/.venv-gef/bin/activate" >> /root/.bashrc 
. /root/.gef/.venv-gef/bin/activate

export PATH="/root/.local/bin:$PATH"
apt-get install -y pkg-config cmake build-essential
uv pip install pwntools

apt-get install -y qemu-user qemu-system

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

apt-get install -y libssl-dev liblzma-dev
cargo install pwninit
