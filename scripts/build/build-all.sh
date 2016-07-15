#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

${SCRIPT_FOLDER}/build-kernel.sh
${SCRIPT_FOLDER}/build-user-space-service.sh
${SCRIPT_FOLDER}/build-test.sh
