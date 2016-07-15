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

/**
 * @file VirgilCommand.h
 * @brief Work with command packages. Create, parse and etc.
 */

#ifndef VIRGIL_COMMAND_H
#define VIRGIL_COMMAND_H

#include <list>
#include <virgil/crypto/VirgilByteArray.h>

using namespace virgil::crypto;

namespace virgil {
    namespace kernel {
        namespace protocol {

            enum VirgilCmd : uint16_t {
                cmdUnknown = 0,
                cmdPing,

                cmdCryptoKeygen,
                cmdCryptoEncryptPassword,
                cmdCryptoDecryptPassword,
                cmdCryptoEncrypt,
                cmdCryptoDecrypt,
                cmdCryptoSign,
                cmdCryptoVerify,
                cmdCryptoHash,

                cmdStorageStore,
                cmdStorageLoad,
                cmdStorageRemove,

                cmdCertificateCreate,
                cmdCertificateGet,
                cmdCertificateVerify,
                cmdCertificateParse,
                cmdCertificateRevoke,
                cmdCertificateCRLInfo,
                cmdCertificateCheckIsRevoked,

                cmdMax
            };

            enum VirgilField : uint16_t {
                fldUnknown = 0,
                fldToken,
                fldCurveType,
                fldPassword,
                fldPrivateKey,
                fldPublicKey,
                fldKeyType,
                fldIdentity,
                fldData,
                fldSignature,
                fldResult,
                fldCertificate,
                fldRootCertificate,
                fldCRLTimeLast,
                fldCRLTimeNext,
                fldHashFunc,
                fldOptional_1,

                fldMax
            };

            enum VirgilResult : uint16_t {
                resOk = 0,
                resGeneralError,

                resMax
            };

            struct VirgilDataElement {
                VirgilDataElement();
                VirgilDataElement(VirgilField _fieldType, const VirgilByteArray & data);

                VirgilField fieldType;
                VirgilByteArray data;
            };
        }
    }
}

using namespace virgil::kernel::protocol;

class VirgilCommand {
public:
    VirgilCommand();
    VirgilCommand(VirgilCmd cmd, uint32_t requestId);
    VirgilCommand(const VirgilByteArray & rawCommandData);
    virtual ~VirgilCommand();

    /**
     * @brief Check is current command valid.
     */
    bool isValid() const;

    /**
     * @brief Clear current command content.
     */
    VirgilCommand & clear();

    /**
     * @brief Prepare new command for send
     * @param cmd - new command type
     * @param requestId - identifier for new command
     */
    VirgilCommand & initSend(VirgilCmd cmd, uint32_t requestId);

    /**
     * @brief Add data field to new command
     * @param field - field type for data
     * @param data - byte array with data
     */
    VirgilCommand & appendData(VirgilField field, const VirgilByteArray & data);

    /**
     * @brief Add data field to new command
     * @param field - field type for data
     * @param time  - time data to be appended
     */
    VirgilCommand & appendTimeData(VirgilField field, time_t timeData);

    /**
     * @brief Serialize current command with data and return byte array
     */
    VirgilByteArray data() const;

    /**
     * @brief Initialize object with raw data. (Parse received command)
     * @param rawCommandData - raw data for parsing
     */
    bool initReceived(const VirgilByteArray & rawCommandData);

    /**
     * @brief Get current command type
     */
    VirgilCmd command() const;


    /**
     * @brief Initialize object with raw data. (Parse received command)
     * @param field - type of field for search
     * @return list with data byte arrays for need field type
     */
    std::list<VirgilByteArray> dataByField(VirgilField field) const;

    /**
     * @brief Returns identifier of current command
     */
    uint32_t id() const;

    /**
     * @brief Fast creation of "ping" command
     * @return Byte array with ping command
     */
    static VirgilByteArray pingCmd();

    /**
     * @brief Fast creation of command with processing result
     * @param cmd - command type which was present in request
     * @param requestId - identifier of request
     * @param result - processing result (for send)
     * @return Byte array with ping command
     */
    static VirgilByteArray resultCmd(VirgilCmd cmd, uint32_t requestId, VirgilResult result);

    /**
     * @brief Template for helper for numbers reading
     */
    template<typename T>
    static T readNum(size_t pos, const VirgilByteArray & data) {
        T res(0);
        const uint8_t * pBytes(reinterpret_cast<const uint8_t *> (data.data() + pos));
        memcpy(&res, pBytes, sizeof (T));
        return res;
    }

    /**
     * @brief Helper for byte array reading
     */
    static VirgilByteArray readByteArray(size_t pos, size_t sz, const VirgilByteArray & data);

private:
    VirgilCmd m_command;
    std::list <VirgilDataElement> m_elements;
    uint32_t m_requestId;
};

#endif /* VIRGIL_COMMAND_H */

