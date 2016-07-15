#!/bin/bash
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

set -ev

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../.."
DOCS_REPO_DIR="${SCRIPT_DIR}/tmp"

# Settings
REPO_PATH=https://github.com/VirgilSecurity/virgil-kernel-module.git
COMMIT_USER="Documentation builder."
COMMIT_EMAIL="kutashenko@gmail.com"
CHANGESET=$(git rev-parse --verify HEAD)

# Gen docs
"${SCRIPT_DIR}/gen-docs.sh"

# Get a clean version of the HTML documentation repo.
rm -rf ${DOCS_REPO_DIR}
mkdir -p ${DOCS_REPO_DIR}
git clone -b gh-pages "${REPO_PATH}" --single-branch ${DOCS_REPO_DIR}

# Copy new documentation
cp -af "${BUILD_DIR}/docs/html/." "${DOCS_REPO_DIR}/"

# Create and commit the documentation repo.
pushd ${DOCS_REPO_DIR}
	git add .
	git config user.name "${COMMIT_USER}"
	git config user.email "${COMMIT_EMAIL}"
	git commit -m "Automated documentation build for changeset ${CHANGESET}."
	git push origin gh-pages
popd

rm -rf ${DOCS_REPO_DIR}