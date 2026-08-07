#!/bin/bash

sudo su

apt-get update
wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh
echo ". $HOME/.gef/.venv-gef/bin/activate" >> $HOME/.bashrc 
. "$HOME/.gef/.venv-gef/bin/activate"

apt-get install -y qemu-user qemu-system

. "$HOME/.local/bin:$PATH"
apt-get install -y pkg-config cmake build-essential
uv pip install pwntools

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

apt-get install -y patchelf libssl-dev liblzma-dev
cargo install pwninit
