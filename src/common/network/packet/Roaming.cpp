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
#include "common/Log.h"
#include "network/Network.h"

using namespace network;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Handles NET_FUNC::ROAMING packets. */

bool Network::PacketHandler::roaming(Network* network, uint32_t peerId, uint32_t streamId, uint64_t now,
    const frame::RTPFNEHeader& fneHeader, const frame::RTPHeader& rtpHeader, const uint8_t* buffer, int length)
{
    (void)peerId;
    (void)streamId;
    (void)now;
    (void)rtpHeader;

    // a link that did not negotiate roaming never carries ROAMING messages (spec 6, policy denial)
    if (!network->isP25RoamingActive()) {
        LogWarning(LOG_NET, "PEER %u P25 ROAMING, link did not negotiate P25 roaming, subFunc = $%02X, dropped",
            network->m_peerId, fneHeader.getSubFunction());
        return true;
    }

    if (buffer == nullptr || length <= 0) {
        LogWarning(LOG_NET, "PEER %u P25 ROAMING, malformed message, subFunc = $%02X, dropped", network->m_peerId,
            fneHeader.getSubFunction());
        return true;
    }

    if (network->m_p25RoamingCallback != nullptr) {
        network->m_p25RoamingCallback(fneHeader.getSubFunction(), buffer, static_cast<uint32_t>(length));
    }

    return true;
}
