#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OPENWRT_INTEGRATION_FOLDER="${SCRIPT_FOLDER}/../../integration/openwrt"
RED='\033[0;31m'
NC='\033[0m' # No Color

if [ -z "${1}" ]; then
	echo -e "${RED} Script usage: "
	echo -e "\t\topenwrt-prepare.sh <path to OpenWrt folder>${NC}"
	exit -1
fi

rm -rf "${1}/tools/cmake"
cp -rf "${OPENWRT_INTEGRATION_FOLDER}/cmake"                  "${1}/tools/"
cp -rf "${OPENWRT_INTEGRATION_FOLDER}/virgil-security"        "${1}/package/libs/"
cp -rf "${OPENWRT_INTEGRATION_FOLDER}/virgil-security-kernel" "${1}/package/kernel/"
