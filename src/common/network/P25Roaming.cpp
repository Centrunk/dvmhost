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
#include "network/RawFrameQueue.h"

using namespace network;
using namespace network::roaming;

#include <cmath>
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

        // access is 0 none, 1 full or 2 emergency only, and only flags bit 7 (radio inhibited) is defined; an
        //  undefined value must not be read as a grant of service
        if (out.access > RoamAccess::EMERGENCY_ONLY || (out.flags | ROAM_FLAG_RADIO_INHIBITED) != ROAM_FLAG_RADIO_INHIBITED) {
            return RoamDecode::OUT_OF_RANGE;
        }
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

/* Gets the exact length of a single SUID announcement. */

uint32_t RoamingCodec::announcementLength(uint8_t subFunc)
{
    switch (subFunc) {
    case NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REG_SUID:
    case NET_SUBFUNC::ANNC_SUBFUNC_UNIT_DEREG_SUID:
    case NET_SUBFUNC::ANNC_SUBFUNC_GRP_UNAFFIL_SUID:
        return MSG_ANNC_UNIT_REG_SUID_LEN;
    case NET_SUBFUNC::ANNC_SUBFUNC_GRP_AFFIL_SUID:
        return MSG_ANNC_GRP_AFFIL_SUID_LEN;
    default:
        return 0U;
    }
}

/* Gets the entry size of a bulk SUID announcement. */

uint32_t RoamingCodec::bulkEntryLength(uint8_t subFunc)
{
    switch (subFunc) {
    case NET_SUBFUNC::ANNC_SUBFUNC_UNIT_REGS_SUID:
        return MSG_ANNC_UNIT_REG_SUID_LEN;
    case NET_SUBFUNC::ANNC_SUBFUNC_AFFILS_SUID:
        return MSG_ANNC_GRP_AFFIL_SUID_LEN;
    default:
        return 0U;
    }
}

/* Encodes a single SUID announcement. */

uint32_t RoamingCodec::encodeSuidAnnouncement(uint8_t subFunc, const SuidAnnouncement& entry, uint8_t* buffer, uint32_t bufferLen)
{
    const uint32_t length = announcementLength(subFunc);
    if (buffer == nullptr || length == 0U || bufferLen < length || !entry.suid.valid()) {
        return 0U;
    }

    const bool withTalkgroup = (length == MSG_ANNC_GRP_AFFIL_SUID_LEN);
    if (withTalkgroup && entry.talkgroup > ROAM_MAX_UNIT_ID) {
        return 0U;
    }

    writeAnnouncementEntry(withTalkgroup, entry, buffer, 0U);
    return length;
}

/* Decodes a single SUID announcement. */

bool RoamingCodec::decodeSuidAnnouncement(uint8_t subFunc, const uint8_t* data, uint32_t length, SuidAnnouncement& entry)
{
    const uint32_t expected = announcementLength(subFunc);
    if (data == nullptr || expected == 0U || length != expected) {
        return false;
    }

    SuidAnnouncement out;
    if (!readAnnouncementEntry(expected == MSG_ANNC_GRP_AFFIL_SUID_LEN, data, 0U, out)) {
        return false;
    }

    entry = out;
    return true;
}

/* Encodes a bulk SUID announcement. */

std::vector<uint8_t> RoamingCodec::encodeSuidBulk(uint8_t subFunc, const std::vector<SuidAnnouncement>& entries)
{
    const uint32_t entryLen = bulkEntryLength(subFunc);
    if (entryLen == 0U) {
        return std::vector<uint8_t>();
    }

    // the payload must fit one network frame
    if (entries.size() > (size_t)((DATA_PACKET_LENGTH - MSG_ANNC_SUID_BULK_HDR_LEN) / entryLen)) {
        return std::vector<uint8_t>();
    }

    const bool withTalkgroup = (entryLen == MSG_ANNC_GRP_AFFIL_SUID_LEN);
    for (const SuidAnnouncement& entry : entries) {
        if (!entry.suid.valid() || (withTalkgroup && entry.talkgroup > ROAM_MAX_UNIT_ID)) {
            return std::vector<uint8_t>();
        }
    }

    const uint32_t count = (uint32_t)entries.size();
    std::vector<uint8_t> payload(MSG_ANNC_SUID_BULK_HDR_LEN + (count * entryLen), 0x00U);
    SET_UINT32(count, payload.data(), 0U);

    uint32_t offs = MSG_ANNC_SUID_BULK_HDR_LEN;
    for (const SuidAnnouncement& entry : entries) {
        writeAnnouncementEntry(withTalkgroup, entry, payload.data(), offs);
        offs += entryLen;
    }

    return payload;
}

/* Decodes a bulk SUID announcement. */

bool RoamingCodec::decodeSuidBulk(uint8_t subFunc, const uint8_t* data, uint32_t length, std::vector<SuidAnnouncement>& entries)
{
    const uint32_t entryLen = bulkEntryLength(subFunc);
    if (data == nullptr || entryLen == 0U || length < MSG_ANNC_SUID_BULK_HDR_LEN) {
        return false;
    }

    const uint32_t count = GET_UINT32(data, 0U);
    const uint32_t available = (length - MSG_ANNC_SUID_BULK_HDR_LEN) / entryLen;

    // count is compared first, so the multiplication below cannot overflow
    if (count != available || length != MSG_ANNC_SUID_BULK_HDR_LEN + (count * entryLen)) {
        return false;
    }

    const bool withTalkgroup = (entryLen == MSG_ANNC_GRP_AFFIL_SUID_LEN);
    std::vector<SuidAnnouncement> out;
    out.reserve(count);

    uint32_t offs = MSG_ANNC_SUID_BULK_HDR_LEN;
    for (uint32_t i = 0U; i < count; i++) {
        SuidAnnouncement entry;
        if (!readAnnouncementEntry(withTalkgroup, data, offs, entry)) {
            return false;
        }

        out.push_back(entry);
        offs += entryLen;
    }

    entries.swap(out);
    return true;
}

/* Builds the RPTC p25Roaming JSON object. */

json::object RoamingCodec::buildConfig(uint32_t netId, uint32_t sysId, uint8_t rfssId)
{
    uint32_t version = ROAM_CONFIG_VERSION;
    uint32_t rfss = rfssId;

    json::object roam = json::object();
    roam["version"].set<uint32_t>(version);
    roam["netId"].set<uint32_t>(netId);
    roam["sysId"].set<uint32_t>(sysId);
    roam["rfssId"].set<uint32_t>(rfss);
    return roam;
}

/* Parses the RPTC p25Roaming object. */

bool RoamingCodec::parseConfig(const json::object& config, RoamingPeerConfig& peer)
{
    auto it = config.find("p25Roaming");
    if (it == config.end() || !it->second.is<json::object>()) {
        return false;
    }

    const json::object& roam = it->second.get<json::object>();

    uint32_t version = 0U;
    uint32_t netId = 0U;
    uint32_t sysId = 0U;
    uint32_t rfssId = 0U;
    if (!readConfigNumber(roam, "version", true, version) || version != ROAM_CONFIG_VERSION) {
        return false;
    }

    if (!readConfigNumber(roam, "netId", true, netId) || !readConfigNumber(roam, "sysId", true, sysId)) {
        return false;
    }

    // an absent rfssId is a downstream FNE (0); a present but invalid one is rejected
    if (!readConfigNumber(roam, "rfssId", false, rfssId)) {
        return false;
    }

    if (netId == 0U || sysId == 0U || !SUID::validSystem(netId, sysId) || rfssId > 0xFFU) {
        return false;
    }

    peer.netId = netId;
    peer.sysId = sysId;
    peer.rfssId = (uint8_t)rfssId;
    return true;
}

/* Encodes the RPTC ACK payload. */

uint32_t RoamingCodec::encodeConfigAck(uint8_t* payload, uint32_t payloadLen, bool capable, uint32_t netId, uint32_t sysId)
{
    if (payload == nullptr || payloadLen < 1U) {
        return 0U;
    }

    if (!capable) {
        payload[0U] = CONFIG_ACK_ALT_DIAG_PORT;
        return 1U;
    }

    if (payloadLen < CONFIG_ACK_ROAMING_LEN || netId == 0U || sysId == 0U || !SUID::validSystem(netId, sysId)) {
        return 0U;
    }

    payload[0U] = CONFIG_ACK_ALT_DIAG_PORT | CONFIG_ACK_ROAMING_CAPABLE;            // Flags
    SET_UINT24(netId, payload, 1U);                                                 // Master WACN ID
    SET_UINT16(sysId, payload, 4U);                                                 // Master System ID
    return CONFIG_ACK_ROAMING_LEN;
}

/* Decodes the RPTC ACK payload. */

bool RoamingCodec::decodeConfigAck(const uint8_t* payload, uint32_t length, bool& capable, uint32_t& netId, uint32_t& sysId)
{
    if (payload == nullptr || length < 1U) {
        return false;
    }

    if ((payload[0U] & CONFIG_ACK_ROAMING_CAPABLE) == 0x00U) {
        capable = false;
        return true;
    }

    if (length < CONFIG_ACK_ROAMING_LEN) {
        return false;
    }

    const uint32_t masterNetId = GET_UINT24(payload, 1U);
    const uint32_t masterSysId = GET_UINT16(payload, 4U);
    if (masterNetId == 0U || masterSysId == 0U || !SUID::validSystem(masterNetId, masterSysId)) {
        return false;
    }

    capable = true;
    netId = masterNetId;
    sysId = masterSysId;
    return true;
}

/* Writes the source WACN ID and System ID into a GRANT_REQ message. */

bool RoamingCodec::encodeGrantSource(uint8_t* buffer, uint32_t netId, uint32_t sysId)
{
    if (buffer == nullptr || !SUID::validSystem(netId, sysId)) {
        return false;
    }

    SET_UINT24(netId, buffer, 4U);                                                  // Source WACN ID
    SET_UINT16(sysId, buffer, 7U);                                                  // Source System ID
    return true;
}

/* Reads the source WACN ID and System ID from a GRANT_REQ message. */

bool RoamingCodec::decodeGrantSource(const uint8_t* buffer, uint32_t length, uint32_t& netId, uint32_t& sysId)
{
    if (buffer == nullptr || length < ROAM_GRANT_REQ_LEN) {
        return false;
    }

    const uint32_t srcNetId = GET_UINT24(buffer, 4U);
    const uint32_t srcSysId = GET_UINT16(buffer, 7U);
    if (!SUID::validSystem(srcNetId, srcSysId)) {
        return false;
    }

    netId = srcNetId;
    sysId = srcSysId;
    return true;
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

/* Writes one SUID announcement entry. */

void RoamingCodec::writeAnnouncementEntry(bool withTalkgroup, const SuidAnnouncement& entry, uint8_t* buffer, uint32_t offset)
{
    SET_UINT24(entry.suid.unitId, buffer, offset);                                  // Unit ID
    if (withTalkgroup) {
        SET_UINT24(entry.talkgroup, buffer, offset + 3U);                           // Talkgroup
        SET_UINT24(entry.suid.netId, buffer, offset + 6U);                          // WACN ID
        SET_UINT16(entry.suid.sysId, buffer, offset + 9U);                          // System ID
    }
    else {
        SET_UINT24(entry.suid.netId, buffer, offset + 3U);                          // WACN ID
        SET_UINT16(entry.suid.sysId, buffer, offset + 6U);                          // System ID
    }
}

/* Reads and range-checks one SUID announcement entry. */

bool RoamingCodec::readAnnouncementEntry(bool withTalkgroup, const uint8_t* buffer, uint32_t offset, SuidAnnouncement& entry)
{
    const uint32_t unitId = GET_UINT24(buffer, offset);
    uint32_t talkgroup = 0U;
    uint32_t netId = 0U;
    uint32_t sysId = 0U;
    if (withTalkgroup) {
        talkgroup = GET_UINT24(buffer, offset + 3U);
        netId = GET_UINT24(buffer, offset + 6U);
        sysId = GET_UINT16(buffer, offset + 9U);
    }
    else {
        netId = GET_UINT24(buffer, offset + 3U);
        sysId = GET_UINT16(buffer, offset + 6U);
    }

    if (!SUID::validSystem(netId, sysId)) {
        return false;
    }

    entry.suid.netId = netId;
    entry.suid.sysId = sysId;
    entry.suid.unitId = unitId;
    entry.talkgroup = talkgroup;
    return true;
}

/* Reads an untrusted JSON number as an exact unsigned integer. */

bool RoamingCodec::readConfigNumber(const json::object& object, const char* key, bool required, uint32_t& value)
{
    auto it = object.find(key);
    if (it == object.end()) {
        value = 0U;
        return !required;
    }

    // a value already typed as an integer (locally built objects) is exact
    if (!it->second.is<double>()) {
        if (!it->second.is<uint32_t>()) {
            return false;
        }

        value = it->second.get<uint32_t>();
        return true;
    }

    // validate the double before any integer conversion; the conversion of an out-of-range double is undefined

    const double number = it->second.get<double>();
    if (!(number >= 0.0) || number != std::floor(number) || number > 4294967295.0) {
        return false;
    }

    value = (uint32_t)number;
    return true;
}
