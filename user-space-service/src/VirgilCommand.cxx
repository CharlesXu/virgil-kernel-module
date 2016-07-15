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

#include <iostream>

#include "VirgilCommand.h"
#include "helpers/VirgilLog.h"

#pragma pack(push,1)

struct packageField {
    uint16_t type;
    uint32_t data_sz;

    union {
        void * p;
        uint8_t pad[8];
    } data;
};

#pragma pack(pop)

VirgilDataElement::VirgilDataElement() : fieldType(fldUnknown) {

}

VirgilDataElement::VirgilDataElement(VirgilField _fieldType, const VirgilByteArray & _data) : fieldType(_fieldType), data(_data) {

}

VirgilCommand::VirgilCommand() {
    clear();
}

VirgilCommand::VirgilCommand(VirgilCmd cmd, uint32_t requestId) {
    initSend(cmd, requestId);
}

VirgilCommand::VirgilCommand(const VirgilByteArray & rawCommandData) {
    initReceived(rawCommandData);
}

VirgilCommand::~VirgilCommand() {
}

template<typename T>
static VirgilByteArray & operator<<(VirgilByteArray & data, T number) {
    uint8_t * pBytes(reinterpret_cast<uint8_t *> (& number));
    for (int i = 0; i < sizeof (number); ++i) {
        data.push_back(pBytes[i]);
    }
    return data;
}

static VirgilByteArray & operator<<(VirgilByteArray & data, const VirgilByteArray & additionData) {
    data.insert(data.end(), additionData.begin(), additionData.end());
    return data;
}

VirgilCommand & VirgilCommand::clear() {
    m_command = cmdUnknown;
    m_elements.clear();
    m_requestId = 0;
    return *this;
}

VirgilCommand & VirgilCommand::initSend(VirgilCmd cmd, uint32_t requestId) {
    clear();
    m_command = cmd;
    m_requestId = requestId;
    return *this;
}

VirgilCommand & VirgilCommand::appendData(VirgilField field, const VirgilByteArray & data) {
    m_elements.push_back(VirgilDataElement(field, data));
    return *this;
}

VirgilCommand & VirgilCommand::appendTimeData(VirgilField field, time_t timeData) {
    VirgilByteArray ba;
    ba << timeData;
    m_elements.push_back(VirgilDataElement(field, ba));
    return *this;
}

VirgilByteArray VirgilCommand::data() const {
    VirgilByteArray res;
    VirgilByteArray payload;

    res << m_requestId << m_command << static_cast<uint16_t> (m_elements.size());
    for (const auto & el : m_elements) {
        res << el.fieldType
                << static_cast<uint32_t> (el.data.size())
                << uint32_t(0)
                << uint32_t(0);
        payload << el.data;
    }

    res << payload;
    return res;
}

VirgilByteArray VirgilCommand::readByteArray(size_t pos, size_t sz, const VirgilByteArray & data) {
    VirgilByteArray res;
    if (data.size() >= (pos + sz)) {
        res.insert(res.end(), data.begin() + pos, data.begin() + pos + sz);
    }
    return res;
}

bool VirgilCommand::initReceived(const VirgilByteArray & rawCommandData) {
    clear();
    size_t pos(0);

    m_requestId = readNum <uint32_t> (pos, rawCommandData);
    pos += sizeof (m_requestId);

    const uint16_t _cmd(readNum <uint16_t> (pos, rawCommandData));
    pos += sizeof (_cmd);

    if (_cmd == static_cast<uint16_t> (cmdUnknown) ||
            _cmd >= static_cast<uint16_t> (cmdMax)) {
        return false;
    }

    m_command = static_cast<VirgilCmd> (_cmd);

    const uint16_t _elementsCount(readNum <uint16_t> (pos, rawCommandData));
    pos += sizeof (_elementsCount);

    if (_elementsCount < 1 || _elementsCount > 50) {
        return false;
    }

    int payloadPos(pos + sizeof (packageField) * _elementsCount);

    for (int i = 0; i < _elementsCount; ++i) {
        const uint16_t _fldType(readNum <uint16_t> (pos, rawCommandData));
        pos += sizeof (_fldType);

        if (_fldType == static_cast<uint16_t> (fldUnknown) ||
                _fldType >= static_cast<uint16_t> (fldMax)) {
            return false;
        }

        const uint32_t _dataSize(readNum <uint32_t> (pos, rawCommandData));
        pos += sizeof (_dataSize);
        pos += sizeof (uint32_t);
        pos += sizeof (uint32_t);

        const VirgilByteArray _data(readByteArray(payloadPos, _dataSize, rawCommandData));

        payloadPos += _dataSize;

        m_elements.push_back(VirgilDataElement(static_cast<VirgilField> (_fldType), _data));
    }

    return true;
}

VirgilCmd VirgilCommand::command() const {
    return m_command;
}

bool VirgilCommand::isValid() const {
    return m_requestId > 0 && m_command != cmdUnknown && m_command < cmdMax;
}

std::list<VirgilByteArray> VirgilCommand::dataByField(VirgilField field) const {
    std::list<VirgilByteArray> res;

    for (const auto & el : m_elements) {
        if (el.fieldType == field) {
            res.push_back(el.data);
        }
    }
    return res;
}

uint32_t VirgilCommand::id() const {
    return m_requestId;
}

VirgilByteArray VirgilCommand::pingCmd() {
    return VirgilCommand(cmdPing, 0).data();
}

VirgilByteArray VirgilCommand::resultCmd(VirgilCmd cmd, uint32_t requestId, VirgilResult result) {
    VirgilByteArray resultBytes;
    resultBytes << result;
    return VirgilCommand(cmd, requestId)
            .appendData(fldResult, resultBytes)
            .data();
}
