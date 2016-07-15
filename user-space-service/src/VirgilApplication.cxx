/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "VirgilApplication.h"
#include "VirgilCRLProcessor.h"
#include "VirgilCommand.h"

#include "signals/Delegate.h"
#include "helpers/VirgilLog.h"

#include "commands/VirgilCmdCrypto.h"
#include "VirgilCertificates.h"
#include "VirgilParams.h"
#include "commands/VirgilCmdStorage.h"
#include "commands/VirgilCmdCertificates.h"

#include <iostream>

VirgilApplication::VirgilApplication() :
m_kernelCommunicator(nullptr) {
}

VirgilApplication::~VirgilApplication() {
    delete m_kernelCommunicator;
}

bool VirgilApplication::exec() {
    static bool inExecution(false);

    if (inExecution) return false;
    inExecution = true;

    LOG("Service start ...");

    LOG("Prepare kernel communicator ... ");

    // Create kernel communicator and connect all signals
    m_kernelCommunicator = new VirgilNetlinkCommunicator;
    m_kernelCommunicator->fireReady.Connect(this, &VirgilApplication::onCommunicationStart);
    m_kernelCommunicator->fireNotReady.Connect(this, &VirgilApplication::onCommunicationStop);
    m_kernelCommunicator->fireDataReceived.Connect(this, &VirgilApplication::onDataReceived);

    // Start crl processing thread
    VirgilCRLProcessor::instance();

    // Send Ping command to thread
    m_kernelCommunicator->send(VirgilCommand::pingCmd());

    // Infinitive sleep
    std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::hours(std::numeric_limits<int>::max()));

    return true;
}

void VirgilApplication::onCommunicationStart() {
    LOG("Communication start ...");
}

void VirgilApplication::onCommunicationStop() {
    LOG("Communication stop ...");
}

void VirgilApplication::sendResult(const VirgilCommand & command, VirgilResult result) {
    m_kernelCommunicator->send(VirgilCommand::resultCmd(command.command(), command.id(), result));
}

void VirgilApplication::onDataReceived(int from, const VirgilByteArray & data) {
    const VirgilCommand _cmd(data);

    if (!_cmd.isValid()) {
        if (data.size() > 1) LOG("ERROR: data not valid");
        return;
    }

    VirgilByteArray answer;

    try {
        switch (_cmd.command()) {
            case cmdCryptoKeygen:
            case cmdCryptoEncryptPassword:
            case cmdCryptoDecryptPassword:
            case cmdCryptoEncrypt:
            case cmdCryptoDecrypt:
            case cmdCryptoSign:
            case cmdCryptoVerify:
            case cmdCryptoHash:
            {
                answer = VirgilCmdCrypto::process(_cmd);
            }
                break;

            case cmdStorageStore:
            case cmdStorageLoad:
            case cmdStorageRemove:
            {
                answer = VirgilCmdDataStorage::process(_cmd);
            }
                break;

            case cmdCertificateCreate:
            case cmdCertificateGet:
            case cmdCertificateVerify:
            case cmdCertificateParse:
            case cmdCertificateRevoke:
            case cmdCertificateCRLInfo:
            case cmdCertificateCheckIsRevoked:
            {
                answer = VirgilCmdCertificates::process(_cmd);
            }
                break;

            default:
            {
                LOG("Unknown");
            }
        }
    } catch (...) {
        answer.clear();
    }

    if (answer.empty()) {
        sendResult(_cmd, resGeneralError);
    } else {
        m_kernelCommunicator->send(answer);
    }
}
