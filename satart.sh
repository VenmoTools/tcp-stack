#!/bin/zsh

exe_path=$(pwd)/target/release/tcp-stack
ipaddress=192.168.3.1/24

cargo build --release

sudo setcap cap_net_admin=eip "$exe_path"

$exe_path&
pid=$!
sudo ip addr add $ipaddress dev tcp0
sudo ip link set up dev tcp0
trap "kill $pid" INT TERM
wait $pid
