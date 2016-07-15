#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OPENWRT_CREDENTIALS_FOLDER="${SCRIPT_FOLDER}/../../integration/test-credentials"
RED='\033[0;31m'
NC='\033[0m' # No Color

if [ -z "${1}" ]; then
	echo -e "${RED} Script usage: "
	echo -e "\t\topenwrt-copy-test-credentials.sh <IP of destination device>${NC}"
	exit -1
fi

scp "${OPENWRT_CREDENTIALS_FOLDER}/_vpasswd" root@${1}:/root/.vpasswd
scp "${OPENWRT_CREDENTIALS_FOLDER}/_vprivkey" root@${1}:/root/.vprivkey
scp "${OPENWRT_CREDENTIALS_FOLDER}/_vtoken" root@${1}:/root/.vtoken

