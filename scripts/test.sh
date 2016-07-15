#!/bin/bash

printf "\ec"

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

${SCRIPT_FOLDER}/build/build-all.sh

sudo killall -9 virgil-service
sudo rmmod -f virgil-kernel-test
sudo rmmod -f virgil-kernel

sleep 1s

sudo insmod ${SCRIPT_FOLDER}/../kernel-module/virgil-kernel.ko

sleep 1s
#valgrind /usr/bin/virgil-service &
#sudo killall -9 virgil-service
#/usr/bin/virgil-service &
#sleep 1s

sudo insmod ${SCRIPT_FOLDER}/../kernel-module-tests/virgil-kernel-test.ko
