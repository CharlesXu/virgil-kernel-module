#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

printf "\ec"
cppcheck --enable=all -I "${SCRIPT_FOLDER}/../../user/include" "${SCRIPT_FOLDER}/../../user/src"
