#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

printf "\ec"
cppcheck --enable=all "${SCRIPT_FOLDER}/../../kernel-module"
