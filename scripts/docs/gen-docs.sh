#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCS_FOLDER="${SCRIPT_FOLDER}/../../docs"

pushd "${DOCS_FOLDER}"
	doxygen
popd
