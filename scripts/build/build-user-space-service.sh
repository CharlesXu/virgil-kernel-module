#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

VIRGIL_SERVICE_APP="virgil-service"
BIN_PATH="/usr/bin"

# Build user mode application
pushd "${SCRIPT_FOLDER}/../user-space-service/"
	cmake .
	make -j9


	if [ ! -f "${BIN_PATH}/${VIRGIL_SERVICE_APP}" ]; then
		while true; do
			echo ""
	    		read -p "Need to create symlink to Virgil Service App. Do you accept this [yes|no] ?" yn
    			case $yn in
        			[Yy]* ) sudo ln -s "$(pwd)/${VIRGIL_SERVICE_APP}" "${BIN_PATH}/${VIRGIL_SERVICE_APP}"; break;;
        			[Nn]* ) exit;;
        			* ) echo "Please answer yes or no.";;
    			esac
		done
	fi

popd

