// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "fne/network/RoamingConfig.h"

using namespace network;
using namespace network::roaming;

#include <cctype>
#include <cstdlib>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the RoamingConfig class. */

RoamingConfig::RoamingConfig() :
    m_enabled(false),
    m_netId(0U),
    m_sysId(0U),
    m_expires(ROAM_DEFAULT_EXPIRES)
{
    /* stub */
}

/* Loads system.p25NetId, system.p25SysId and system.p25RoamingExpires. */

RoamingConfigLoad::E RoamingConfig::load(yaml::Node& systemConf)
{
    m_enabled = false;
    m_netId = 0U;
    m_sysId = 0U;
    m_expires = systemConf["p25RoamingExpires"].as<uint32_t>(ROAM_DEFAULT_EXPIRES);

    const std::string netText = systemConf["p25NetId"].as<std::string>("");
    const std::string sysText = systemConf["p25SysId"].as<std::string>("");
    if (netText.empty() && sysText.empty()) {
        return RoamingConfigLoad::OK;
    }

    uint32_t netId = 0U;
    uint32_t sysId = 0U;
    if (!parseHex(netText, ROAM_MAX_WACN, netId)) {
        return RoamingConfigLoad::INVALID;
    }

    // the protected WACN range fails startup whatever p25SysId holds
    if (netId >= ROAM_WACN_PROTECTED_START && netId <= ROAM_WACN_PROTECTED_END) {
        return RoamingConfigLoad::PROTECTED_WACN;
    }

    if (!parseHex(sysText, ROAM_MAX_SYSID, sysId)) {
        return RoamingConfigLoad::INVALID;
    }

    // both zero is the same as both absent: no P25 identity (spec 2.1)
    if (netId == 0U && sysId == 0U) {
        return RoamingConfigLoad::OK;
    }

    if (netId == 0U || sysId == 0U) {
        return RoamingConfigLoad::INVALID;
    }

    if (m_expires <= ROAM_MIN_EXPIRES) {
        return RoamingConfigLoad::EXPIRES_TOO_SHORT;
    }

    m_netId = netId;
    m_sysId = sysId;
    m_enabled = true;
    return RoamingConfigLoad::OK;
}

/* Sets the identity directly. */

bool RoamingConfig::set(uint32_t netId, uint32_t sysId, uint32_t expires)
{
    m_enabled = false;
    m_netId = 0U;
    m_sysId = 0U;
    m_expires = expires;

    if (netId == 0U || sysId == 0U || !SUID::validSystem(netId, sysId) || expires <= ROAM_MIN_EXPIRES ||
        (netId >= ROAM_WACN_PROTECTED_START && netId <= ROAM_WACN_PROTECTED_END)) {
        return false;
    }

    m_netId = netId;
    m_sysId = sysId;
    m_enabled = true;
    return true;
}

/* Evaluates the p25Roaming object of an RPTC configuration. */

RoamingLogin::E RoamingConfig::evaluateLogin(const json::object& peerConfig, bool neighbor, RoamingPeerConfig& peer) const
{
    peer = RoamingPeerConfig();
    const bool offered = RoamingCodec::parseConfig(peerConfig, peer);

    // an FNE without an identity never negotiates roaming (spec 2.1)
    if (!m_enabled) {
        return RoamingLogin::NOT_CAPABLE;
    }

    // a WACN ID in BEE00 - BEEFF is refused for a peer exactly as for this FNE's own p25NetId (see AGENTS.md); it is
    //  checked first so a downstream FNE (exempt from the mismatch check) cannot bring one in
    if (offered && peer.netId >= ROAM_WACN_PROTECTED_START && peer.netId <= ROAM_WACN_PROTECTED_END) {
        return RoamingLogin::REJECT_PROTECTED_WACN;
    }

    // a host belongs to this system; a different WACN ID or System ID would break every home decision (spec 2.2)
    if (!neighbor && offered && (peer.netId != m_netId || peer.sysId != m_sysId)) {
        return RoamingLogin::REJECT_MISMATCH;
    }

    // Each SU has one Home RFSS (BACA 2.1.3.1.1), found from the WACN ID and System ID of its SUID, so exactly one FNE
    // per system holds the identity. A downstream FNE offering this system's identity would be a second home.
    if (neighbor && offered && peer.netId == m_netId && peer.sysId == m_sysId) {
        return RoamingLogin::SAME_SYSTEM_FNE;
    }

    return offered ? RoamingLogin::CAPABLE : RoamingLogin::NOT_CAPABLE;
}

/* Builds the RPTC ACK payload. */

uint32_t RoamingConfig::buildConfigAck(uint8_t* payload, uint32_t payloadLen) const
{
    return RoamingCodec::encodeConfigAck(payload, payloadLen, m_enabled, m_netId, m_sysId);
}

/* Parses a hexadecimal identity string. */

bool RoamingConfig::parseHex(const std::string& text, uint32_t max, uint32_t& value)
{
    std::string digits = text;
    if (digits.size() >= 2U && digits[0U] == '0' && (digits[1U] == 'x' || digits[1U] == 'X')) {
        digits = digits.substr(2U);
    }

    // at most 8 hexadecimal digits fit 32 bits
    if (digits.empty() || digits.size() > 8U) {
        return false;
    }

    for (char c : digits) {
        if (::isxdigit(static_cast<unsigned char>(c)) == 0) {
            return false;
        }
    }

    const uint32_t parsed = (uint32_t)::strtoul(digits.c_str(), nullptr, 16);
    if (parsed > max) {
        return false;
    }

    value = parsed;
    return true;
}
