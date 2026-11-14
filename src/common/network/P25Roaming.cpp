// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "network/P25Roaming.h"
#include "network/RTPFNEHeader.h"

using namespace network;
using namespace network::roaming;

#include <cstring>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Packs the SUID into its 64-bit table key. */

uint64_t SUID::pack() const
{
    return ((uint64_t)(netId & ROAM_MAX_WACN) << 36) | ((uint64_t)(sysId & ROAM_MAX_SYSID) << 24) |
        (uint64_t)(unitId & ROAM_MAX_UNIT_ID);
}

/* Unpacks a 64-bit SUID table key. */

SUID SUID::unpack(uint64_t key)
{
    SUID suid;
    suid.netId = (uint32_t)((key >> 36) & ROAM_MAX_WACN);
    suid.sysId = (uint32_t)((key >> 24) & ROAM_MAX_SYSID);
    suid.unitId = (uint32_t)(key & ROAM_MAX_UNIT_ID);
    return suid;
}

/* Checks the WACN ID, System ID and Unit ID ranges. */

bool SUID::valid() const
{
    return validSystem(netId, sysId) && unitId <= ROAM_MAX_UNIT_ID;
}

/* Compares two SUIDs. */

bool SUID::operator==(const SUID& other) const
{
    return netId == other.netId && sysId == other.sysId && unitId == other.unitId;
}

/* Checks the WACN ID and System ID ranges. */

bool SUID::validSystem(uint32_t netId, uint32_t sysId)
{
    return netId <= ROAM_MAX_WACN && sysId <= ROAM_MAX_SYSID;
}

/* Packs a WACN ID and System ID into a 32-bit system table key. */

uint32_t SUID::systemKey(uint32_t netId, uint32_t sysId)
{
    return ((netId & ROAM_MAX_WACN) << 12) | (sysId & ROAM_MAX_SYSID);
}

/* Checks the WACN ID and System ID ranges. */

bool RfssIdentity::valid() const
{
    return SUID::validSystem(netId, sysId);
}

/* Compares two RFSS identities. */

bool RfssIdentity::operator==(const RfssIdentity& other) const
{
    return netId == other.netId && sysId == other.sysId && rfssId == other.rfssId;
}

/* Gets the exact length of a ROAMING message. */

uint32_t RoamingCodec::messageLength(uint8_t subFunc)
{
    switch (subFunc) {
    case NET_SUBFUNC::ROAM_SERVING_REG:
        return MSG_ROAM_SERVING_REG_LEN;
    case NET_SUBFUNC::ROAM_SERVING_REG_RSP:
        return MSG_ROAM_SERVING_REG_RSP_LEN;
    case NET_SUBFUNC::ROAM_SERVING_DEREG:
        return MSG_ROAM_SERVING_DEREG_LEN;
    case NET_SUBFUNC::ROAM_SERVING_DEREG_RSP:
        return MSG_ROAM_SERVING_DEREG_RSP_LEN;
    case NET_SUBFUNC::ROAM_HOME_DEREG:
        return MSG_ROAM_HOME_DEREG_LEN;
    case NET_SUBFUNC::ROAM_HOME_DEREG_RSP:
        return MSG_ROAM_HOME_DEREG_RSP_LEN;
    case NET_SUBFUNC::ROAM_QUERY:
        return MSG_ROAM_QUERY_LEN;
    case NET_SUBFUNC::ROAM_QUERY_RSP:
        return MSG_ROAM_QUERY_RSP_LEN;
    case NET_SUBFUNC::ROAM_GEN_RSP:
        return MSG_ROAM_GEN_RSP_LEN;
    default:
        return 0U;
    }
}

/* Classifies a ROAMING sub-function. */

bool RoamingCodec::isRequest(uint8_t subFunc)
{
    return (subFunc & 0x01U) == 0x00U;
}

/* Encodes a ROAMING message. */

uint32_t RoamingCodec::encode(const RoamingMessage& msg, uint8_t* buffer, uint32_t bufferLen)
{
    const uint32_t length = messageLength(msg.subFunc);
    if (buffer == nullptr || length == 0U || bufferLen < length) {
        return 0U;
    }

    if (msg.subFunc != NET_SUBFUNC::ROAM_GEN_RSP && !msg.suid.valid()) {
        return 0U;
    }

    if ((msg.subFunc == NET_SUBFUNC::ROAM_SERVING_REG || msg.subFunc == NET_SUBFUNC::ROAM_SERVING_DEREG) && !msg.serving.valid()) {
        return 0U;
    }

    ::memset(buffer, 0x00U, length);

    buffer[0U] = msg.version;                                                       // Version
    buffer[1U] = msg.hopCount;                                                      // Hop Count
    SET_UINT32(msg.txnId, buffer, 2U);                                              // Transaction ID

    if (msg.subFunc == NET_SUBFUNC::ROAM_GEN_RSP) {
        buffer[6U] = msg.rejectedSubFunc;                                           // Rejected Sub-Function
        buffer[7U] = msg.result;                                                    // Result
        return length;
    }

    writeSUID(msg.suid, buffer, ROAM_HEADER_LEN);

    switch (msg.subFunc) {
    case NET_SUBFUNC::ROAM_SERVING_REG:
        writeRfss(msg.serving, buffer, 14U);
        buffer[20U] = msg.presence;                                                 // Presence
        break;
    case NET_SUBFUNC::ROAM_SERVING_REG_RSP:
        buffer[14U] = msg.result;                                                   // Result
        SET_UINT32(msg.expires, buffer, 15U);                                       // Expires (seconds)
        buffer[19U] = msg.access;                                                   // Access
        buffer[20U] = msg.flags;                                                    // Flags
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG:
        writeRfss(msg.serving, buffer, 14U);
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG_RSP:
    case NET_SUBFUNC::ROAM_HOME_DEREG_RSP:
        buffer[14U] = msg.result;                                                   // Result
        break;
    case NET_SUBFUNC::ROAM_HOME_DEREG:
        buffer[14U] = msg.qualifier;                                                // Qualifier
        break;
    case NET_SUBFUNC::ROAM_QUERY:
        buffer[14U] = msg.queryType;                                                // Query Type
        break;
    case NET_SUBFUNC::ROAM_QUERY_RSP:
        buffer[14U] = msg.result;                                                   // Result
        buffer[15U] = msg.interested;                                               // Interested
        break;
    default:
        break;
    }

    return length;
}

/* Decodes a ROAMING message. */

RoamDecode::E RoamingCodec::decode(uint8_t subFunc, const uint8_t* data, uint32_t length, RoamingMessage& msg)
{
    const uint32_t expected = messageLength(subFunc);
    if (expected == 0U) {
        return RoamDecode::UNKNOWN_SUBFUNC;
    }

    if (data == nullptr || length != expected) {
        return RoamDecode::MALFORMED_LENGTH;
    }

    // decode into a temporary; the caller's message is written only after every check passes
    RoamingMessage out;
    out.subFunc = subFunc;
    out.version = data[0U];
    out.hopCount = data[1U];
    out.txnId = GET_UINT32(data, 2U);

    if (out.version != ROAM_VERSION) {
        return RoamDecode::BAD_VERSION;
    }

    if (subFunc == NET_SUBFUNC::ROAM_GEN_RSP) {
        out.rejectedSubFunc = data[6U];
        out.result = data[7U];
        msg = out;
        return RoamDecode::OK;
    }

    if (!readSUID(data, ROAM_HEADER_LEN, out.suid)) {
        return RoamDecode::OUT_OF_RANGE;
    }

    switch (subFunc) {
    case NET_SUBFUNC::ROAM_SERVING_REG:
        if (!readRfss(data, 14U, out.serving)) {
            return RoamDecode::OUT_OF_RANGE;
        }
        out.presence = data[20U];
        break;
    case NET_SUBFUNC::ROAM_SERVING_REG_RSP:
        out.result = data[14U];
        out.expires = GET_UINT32(data, 15U);
        out.access = data[19U];
        out.flags = data[20U];
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG:
        if (!readRfss(data, 14U, out.serving)) {
            return RoamDecode::OUT_OF_RANGE;
        }
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG_RSP:
    case NET_SUBFUNC::ROAM_HOME_DEREG_RSP:
        out.result = data[14U];
        break;
    case NET_SUBFUNC::ROAM_HOME_DEREG:
        out.qualifier = data[14U];
        break;
    case NET_SUBFUNC::ROAM_QUERY:
        out.queryType = data[14U];
        break;
    case NET_SUBFUNC::ROAM_QUERY_RSP:
        out.result = data[14U];
        out.interested = data[15U];
        break;
    default:
        break;
    }

    msg = out;
    return RoamDecode::OK;
}

/* Decodes only the ROAMING common header. */

RoamDecode::E RoamingCodec::decodeHeader(const uint8_t* data, uint32_t length, uint8_t& version, uint8_t& hopCount, uint32_t& txnId)
{
    if (data == nullptr || length < ROAM_HEADER_LEN) {
        return RoamDecode::MALFORMED_LENGTH;
    }

    version = data[0U];
    hopCount = data[1U];
    txnId = GET_UINT32(data, 2U);
    return RoamDecode::OK;
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Writes a SUID field group. */

void RoamingCodec::writeSUID(const SUID& suid, uint8_t* buffer, uint32_t offset)
{
    SET_UINT24(suid.netId, buffer, offset);                                         // WACN ID
    SET_UINT16(suid.sysId, buffer, offset + 3U);                                    // System ID
    SET_UINT24(suid.unitId, buffer, offset + 5U);                                   // Unit ID
}

/* Reads and range-checks a SUID field group. */

bool RoamingCodec::readSUID(const uint8_t* buffer, uint32_t offset, SUID& suid)
{
    const uint32_t netId = GET_UINT24(buffer, offset);
    const uint32_t sysId = GET_UINT16(buffer, offset + 3U);
    const uint32_t unitId = GET_UINT24(buffer, offset + 5U);
    if (!SUID::validSystem(netId, sysId)) {
        return false;
    }

    suid.netId = netId;
    suid.sysId = sysId;
    suid.unitId = unitId;
    return true;
}

/* Writes an RFSS identity field group. */

void RoamingCodec::writeRfss(const RfssIdentity& rfss, uint8_t* buffer, uint32_t offset)
{
    SET_UINT24(rfss.netId, buffer, offset);                                         // WACN ID
    SET_UINT16(rfss.sysId, buffer, offset + 3U);                                    // System ID
    buffer[offset + 5U] = rfss.rfssId;                                              // RFSS ID
}

/* Reads and range-checks an RFSS identity field group. */

bool RoamingCodec::readRfss(const uint8_t* buffer, uint32_t offset, RfssIdentity& rfss)
{
    const uint32_t netId = GET_UINT24(buffer, offset);
    const uint32_t sysId = GET_UINT16(buffer, offset + 3U);
    if (!SUID::validSystem(netId, sysId)) {
        return false;
    }

    rfss.netId = netId;
    rfss.sysId = sysId;
    rfss.rfssId = buffer[offset + 5U];
    return true;
}
