// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "fne/Defines.h"
#include "common/Log.h"
#include "network/TrafficNetwork.h"
#include "HostFNE.h"

using namespace network;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Handles NET_FUNC::ROAMING packets from downstream peers. */

void TrafficNetwork::PacketHandler::roaming(TrafficNetwork* network, NetPacketRequest* req, uint32_t peerId, uint32_t ssrc, uint32_t streamId, uint64_t now)
{
    (void)ssrc;
    (void)streamId;

    TrafficNetwork::PeerConnectionPtr connection = network->findPeer(peerId);
    if (peerId == 0U || connection == nullptr) {
        return;
    }

    // validate peer (simple validation really)
    std::string ip = udp::Socket::address(req->address);
    if (!connection->connected() || connection->address() != ip) {
        LogWarning(LOG_MASTER, "PEER %u P25 ROAMING from an unauthenticated peer, dropped", peerId);
        return;
    }

    if (req->buffer == nullptr || req->length <= 0) {
        LogWarning(LOG_MASTER, "PEER %u P25 ROAMING, malformed packet, dropped", peerId);
        return;
    }

    // the service checks the link's negotiated capability before parsing
    RoamingLink link;
    link.peerId = peerId;
    link.upstream = false;
    network->m_roaming->process(link, req->fneHeader.getSubFunction(), req->buffer, static_cast<uint32_t>(req->length), now);
}
