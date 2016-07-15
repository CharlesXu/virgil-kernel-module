#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EXT_FOLDER="${SCRIPT_FOLDER}/../ext"
TMP_FOLDER="${SCRIPT_FOLDER}/tmp"

echo "---------------- Prepare Virgil libraries --------------"

echo "Create EXT folder ..."
if [ -d "${EXT_FOLDER}" ]; then
	rm -rf "${EXT_FOLDER}"
fi
mkdir "${EXT_FOLDER}"

echo "Create temporary folder ..."
if [ -d "${TMP_FOLDER}" ]; then
	rm -rf "${TMP_FOLDER}"
fi
mkdir "${TMP_FOLDER}"

pushd "${TMP_FOLDER}"
	echo "Get Virgil C++ SDK ..."
	git clone https://github.com/VirgilSecurity/virgil-sdk-cpp.git

	pushd virgil-sdk-cpp
		git checkout -b 1609-wrapper --track origin/1609-wrapper
		mkdir build
		pushd build
			cmake -DCMAKE_INSTALL_PREFIX="${EXT_FOLDER}" -DINSTALL_EXT_HEADERS=ON ..	
			make -j5
			make install
		popd
	popd
popd

rm -rf "${TMP_FOLDER}"



