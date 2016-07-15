#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Build user mode application
pushd "${SCRIPT_FOLDER}/../../kernel-module-tests/"
	make clean
	make
popd


