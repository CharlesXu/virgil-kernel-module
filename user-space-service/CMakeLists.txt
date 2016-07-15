#
# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil_user_space)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

## Crosscompiling
set (UCLIBC OFF CACHE BOOL "Enable pathches if SDK is build with uClibc++")

# Define enviroment parameters
include (check_pointer_size)
check_pointer_size (POINTER_SIZE)
if (POINTER_SIZE)
    message (STATUS "Compiler pointer size: " ${POINTER_SIZE} " bytes")
else ()
    message (STATUS "Compiler pointer size: UNDEFINED")
endif ()

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Inspect system
set (SYSTEM_ARCH x86)
if (POINTER_SIZE EQUAL 8)
    set (SYSTEM_ARCH x64)
endif ()
string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSTEM_NAME)

# Configure path variables
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")

# Find dependencies
find_package (CURL REQUIRED)
include_directories (${CURL_INCLUDE_DIRS})

if (CMAKE_TOOLCHAIN_FILE)
   list (APPEND CMAKE_ARGS
               -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
)
endif (CMAKE_TOOLCHAIN_FILE)

# Use headers
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/include/commands"  "${CMAKE_CURRENT_SOURCE_DIR}/../ext/include")

# Grab source directory tree
file (GLOB_RECURSE SRC_LIST "src/*.cxx")
foreach (SRC_FILE ${SRC_LIST})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" SRC_REL_PATH ${SRC_FILE})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${SRC_REL_PATH}"
        "${CMAKE_CURRENT_BINARY_DIR}/src/${SRC_REL_PATH}"
        @ONLY
    )
endforeach ()
file (GLOB_RECURSE SRC_LIST "${CMAKE_CURRENT_BINARY_DIR}/src/*.cxx")

# Library search path
link_directories("${CMAKE_CURRENT_SOURCE_DIR}/../ext/lib")

add_executable (virgil_user_space ${SRC_LIST})
target_compile_definitions (virgil_user_space PUBLIC "UCLIBC=$<BOOL:${UCLIBC}>")
target_link_libraries (virgil_user_space
    virgil_sdk
    virgil_crypto
    restless
    mbedx509
    mbedcrypto
    ed25519
    pthread
    ${CURL_LIBRARIES}
)

set_target_properties (virgil_user_space PROPERTIES OUTPUT_NAME "virgil-service")

# Install
install (TARGETS virgil_user_space DESTINATION ${INSTALL_BIN_DIR_NAME})

