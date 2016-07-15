#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Build virgil-kernel
pushd "${SCRIPT_FOLDER}/../../kernel-module/"
	make clean
	make
popd

