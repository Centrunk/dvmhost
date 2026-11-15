// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2023-2026 Bryan Biedenkapp, N2PLL
 *
 */
#include "fne/Defines.h"
#include "common/Log.h"
#include "network/TrafficNetwork.h"
#include "network/callhandler/TagDMRData.h"
#include "network/callhandler/TagP25Data.h"
#include "network/callhandler/TagNXDNData.h"
#include "HostFNE.h"

using namespace network;
using namespace network::callhandler;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Handles NET_FUNC::GRANT_REQ packets. */

void TrafficNetwork::PacketHandler::grantRequest(TrafficNetwork* network, NetPacketRequest* req, uint32_t peerId, uint32_t ssrc, uint32_t streamId, uint64_t now)
{
    TrafficNetwork::PeerConnectionPtr connection = network->findPeer(peerId);
    if (peerId > 0 && connection != nullptr) {
        std::string ip = udp::Socket::address(req->address);

        // validate peer (simple validation really)
        if (connection->connected() && connection->address() == ip) {
            // bytes 4-8 carry the source radio's home WACN ID and System ID; zero means this system; the decoder also
            //  proves the buffer holds a complete GRANT_REQ
            uint32_t srcNetId = 0U;
            uint32_t srcSysId = 0U;
            if (req->length <= 0 || !roaming::RoamingCodec::decodeGrantSource(req->buffer, static_cast<uint32_t>(req->length), srcNetId, srcSysId)) {
                LogWarning(LOG_MASTER, "PEER %u (%s) malformed grant request, length = %d, dropped", peerId,
                    connection->identWithQualifier().c_str(), req->length);
                return;
            }

            const bool ownSystem = (srcNetId == 0U && srcSysId == 0U) ||
                (network->m_roamingConfig.enabled() && srcNetId == network->m_roamingConfig.netId() &&
                 srcSysId == network->m_roamingConfig.sysId());
            if (!ownSystem) {
                // TODO(P25-ROAM): cross-system grant requests are not handled; remove when group and unit-to-unit roaming is supported.
                LogWarning(LOG_MASTER, "PEER %u (%s) grant request for a roaming source ($%05X.$%03X) is not supported, dropped",
                    peerId, connection->identWithQualifier().c_str(), srcNetId, srcSysId);
                return;
            }

            uint32_t srcId = GET_UINT24(req->buffer, 11U);                  // Source Address
            uint32_t dstId = GET_UINT24(req->buffer, 15U);                  // Destination Address

            uint8_t slot = req->buffer[19U];

            bool unitToUnit = (req->buffer[19U] & 0x80U) == 0x80U;

            DVM_STATE state = (DVM_STATE)req->buffer[20U];                  // DVM Mode State
            uint8_t serviceOptions = req->buffer[21U];                     // Service Options
            switch (state) {
            case STATE_DMR:
                if (network->m_dmrEnabled) {
                    if (network->m_tagDMR != nullptr) {
                        network->m_tagDMR->processGrantReq(srcId, dstId, slot, unitToUnit, serviceOptions,
                            peerId, req->rtpHeader.getSequence(), streamId);
                    } else {
                        network->writePeerNAK(peerId, streamId, TAG_DMR_DATA, NET_CONN_NAK_MODE_NOT_ENABLED);
                    }
                }
                break;
            case STATE_P25:
                if (network->m_p25Enabled) {
                    if (network->m_tagP25 != nullptr) {
                        network->m_tagP25->processGrantReq(srcId, dstId, unitToUnit, serviceOptions,
                            peerId, req->rtpHeader.getSequence(), streamId);
                    } else {
                        network->writePeerNAK(peerId, streamId, TAG_P25_DATA, NET_CONN_NAK_MODE_NOT_ENABLED);
                    }
                }
                break;
            case STATE_NXDN:
                if (network->m_nxdnEnabled) {
                    if (network->m_tagNXDN != nullptr) {
                        network->m_tagNXDN->processGrantReq(srcId, dstId, unitToUnit, serviceOptions,
                            peerId, req->rtpHeader.getSequence(), streamId);
                    } else {
                        network->writePeerNAK(peerId, streamId, TAG_NXDN_DATA, NET_CONN_NAK_MODE_NOT_ENABLED);
                    }
                }
                break;
            default:
                network->writePeerNAK(peerId, streamId, TAG_REPEATER_GRANT, NET_CONN_NAK_ILLEGAL_PACKET);
                Utils::dump("Unknown state for grant request from the peer", req->buffer, req->length);
                break;
            }
        }
    }
}

/* Handles NET_FUNC::GRANT_REL packets. */

void TrafficNetwork::PacketHandler::grantRelease(TrafficNetwork* network, NetPacketRequest* req, uint32_t peerId, uint32_t ssrc, uint32_t streamId, uint64_t now)
{
    TrafficNetwork::PeerConnectionPtr connection = network->findPeer(peerId);
    if (peerId == 0U || connection == nullptr)
        return;

    const std::string ip = udp::Socket::address(req->address);
    if (!connection->connected() || connection->address() != ip)
        return;

    const uint32_t srcId = GET_UINT24(req->buffer, 11U);
    const uint32_t dstId = GET_UINT24(req->buffer, 15U);
    const bool unitToUnit = (req->buffer[19U] & 0x80U) == 0x80U;
    const bool failed = (req->buffer[21U] & NET_GRANT_RELEASE_FAILED) == NET_GRANT_RELEASE_FAILED;

    network->processGrantRelease(srcId, dstId, unitToUnit, peerId, failed);
}
