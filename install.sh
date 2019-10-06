#!/bin/sh
set -ex

mkdir -p build
sudo apt-get install libpcap-dev
gcc -std=gnu99 -o nids ./src/main.c -lpcap
