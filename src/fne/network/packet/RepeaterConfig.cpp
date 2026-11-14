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
#include "HostFNE.h"

using namespace network;

#include <cstring>

// ---------------------------------------------------------------------------
//  Global Functions
// ---------------------------------------------------------------------------

namespace
{
    /* Resolves the connection class a peer's RPTC configuration selects. */

    PEER_CONN_CLASS resolveOfferedPeerClass(const json::object& peerConfig)
    {
        // older peers report their class through the sysView and externalPeer booleans (externalPeer wins),
        //  newer peers send peerClass, which overrides both
        PEER_CONN_CLASS peerClass = PEER_CONN_CLASS_STANDARD;

        const json::object::const_iterator sysView = peerConfig.find("sysView");
        if (sysView != peerConfig.end() && sysView->second.is<bool>() && sysView->second.get<bool>()) {
            peerClass = PEER_CONN_CLASS_SYSVIEW;
        }

        const json::object::const_iterator externalPeer = peerConfig.find("externalPeer");
        if (externalPeer != peerConfig.end() && externalPeer->second.is<bool>() && externalPeer->second.get<bool>()) {
            peerClass = PEER_CONN_CLASS_NEIGHBOR;
        }

        const json::object::const_iterator explicitClass = peerConfig.find("peerClass");
        if (explicitClass != peerConfig.end() && explicitClass->second.is<uint32_t>()) {
            uint32_t value = explicitClass->second.get<uint32_t>();
            if (value >= PEER_CONN_CLASS_INVALID)
                value = PEER_CONN_CLASS_STANDARD;
            peerClass = (PEER_CONN_CLASS)value;
        }

        return peerClass;
    }
} // namespace

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Handles NET_FUNC::RPTC packets. */

void TrafficNetwork::PacketHandler::repeaterConfig(TrafficNetwork* network, NetPacketRequest* req, uint32_t peerId, uint32_t ssrc, uint32_t streamId, uint64_t now)
{
    // validate the incoming packet length for a repeater configuration packet
    if (req == nullptr || req->buffer == nullptr || !TrafficNetwork::validRepeaterConfigLength(req->length)) {
        LogWarning(LOG_MASTER, "PEER %u RPTC, malformed packet length", peerId);
        return;
    }

    if (peerId > 0) {
        std::lock_guard<std::mutex> peerGuard(TrafficNetwork::getPeerStateLock(peerId));

        TrafficNetwork::PeerConnectionPtr connection = network->findPeer(peerId);
        if (connection != nullptr) {
            connection->lastPing(now);

            if (connection->connectionState() == NET_STAT_WAITING_CONFIG) {
                const size_t payloadLength = (size_t)(req->length - REPEATER_PCKT_HDR_LEN);
                std::string payload((const char *)(req->buffer + REPEATER_PCKT_HDR_LEN), payloadLength);

                // parse JSON body
                json::value v;
                std::string err = json::parse(v, payload);
                if (!err.empty()) {
                    LogWarning(LOG_MASTER, "PEER %u RPTC NAK, supplied invalid configuration data", peerId);
                    network->writePeerNAK(peerId, TAG_REPEATER_AUTH, NET_CONN_NAK_INVALID_CONFIG_DATA, req->address, req->addrLen);
                    network->disconnectPeer(peerId, connection);
                }
                else  {
                    // ensure parsed JSON is an object
                    if (!v.is<json::object>()) {
                        LogWarning(LOG_MASTER, "PEER %u RPTC NAK, supplied invalid configuration data", peerId);
                        network->writePeerNAK(peerId, TAG_REPEATER_AUTH, NET_CONN_NAK_INVALID_CONFIG_DATA, req->address, req->addrLen);
                        network->disconnectPeer(peerId, connection);
                    }
                    else {
                        // validate the P25 identity before any connection state changes (spec 2.2, 3.1)
                        json::object offered = v.get<json::object>();
                        // the neighbor decision uses the same precedence as the peer class assigned below
                        const bool neighborOffer = resolveOfferedPeerClass(offered) == PEER_CONN_CLASS_NEIGHBOR;
                        roaming::RoamingPeerConfig peerRoaming;
                        const RoamingLogin::E roamingLogin = network->m_roamingConfig.evaluateLogin(offered, neighborOffer, peerRoaming);
                        if (roamingLogin == RoamingLogin::REJECT_MISMATCH) {
                            LogError(LOG_MASTER, "PEER %u RPTC NAK, P25 identity mismatch, peer netId = $%05X, sysId = $%03X, system netId = $%05X, sysId = $%03X, check the host rfssConfig netId and sysId",
                                peerId, peerRoaming.netId, peerRoaming.sysId, network->m_roamingConfig.netId(), network->m_roamingConfig.sysId());
                            network->writePeerNAK(peerId, TAG_REPEATER_CONFIG, NET_CONN_NAK_INVALID_CONFIG_DATA, req->address, req->addrLen);
                            network->disconnectPeer(peerId, connection);
                            return;
                        }

                        connection->config(v.get<json::object>());
                        connection->connectionState(NET_STAT_RUNNING);
                        connection->connected(true);
                        connection->pingsReceived(0U);
                        connection->lastPing(now);
                        connection->missedMetadataUpdates(0U);

                        lookups::PeerId peerEntry = network->m_peerListLookup->find(peerId);
                        if (!peerEntry.peerDefault()) {
                            if (peerEntry.hasCallPriority()) {
                                connection->hasCallPriority(peerEntry.hasCallPriority());
                                LogInfoEx(LOG_MASTER, "PEER %u >> Has Call Priority", peerId);
                            }
                        }

                        network->storePeer(peerId, connection);

                        // attach extra notification data to the RPTC ACK to notify the peer of 
                        // the use of the alternate diagnostic port
                        // payload byte 0 bit 7 always marks the alternate diagnostics port; bit 6 and the master P25
                        //  identity are added when this FNE has a P25 identity (spec 3.1)
                        uint8_t buffer[roaming::CONFIG_ACK_ROAMING_LEN];
                        ::memset(buffer, 0x00U, sizeof(buffer));
                        uint32_t ackLength = network->m_roamingConfig.buildConfigAck(buffer, sizeof(buffer));
                        if (ackLength == 0U) {
                            buffer[0U] = roaming::CONFIG_ACK_ALT_DIAG_PORT;
                            ackLength = 1U;
                        }

                        connection->p25RoamingCapable(roamingLogin == RoamingLogin::CAPABLE);
                        connection->p25NetId(peerRoaming.netId);
                        connection->p25SysId(peerRoaming.sysId);
                        connection->p25RfssId(peerRoaming.rfssId);
                        if (roamingLogin == RoamingLogin::CAPABLE) {
                            LogInfoEx(LOG_MASTER, "PEER %u >> P25 Roaming [netId $%05X, sysId $%03X, rfssId $%02X]", peerId,
                                peerRoaming.netId, peerRoaming.sysId, peerRoaming.rfssId);
                        }

                        json::object peerConfig = connection->config();

                        std::string identity = "* UNK *";
                        if (peerConfig["identity"].is<std::string>()) {
                            identity = peerConfig["identity"].getDefault<std::string>("* UNK *");
                            connection->identity(identity);
                            LogInfoEx(LOG_MASTER, "PEER %u >> Identity [%8s]", peerId, identity.c_str());
                        }

                        if (peerConfig["software"].is<std::string>()) {
                            std::string software = peerConfig["software"].get<std::string>();
                            LogInfoEx(LOG_MASTER, "PEER %u >> Software Version [%s]", peerId, software.c_str());
                        }

                        /*
                        ** bryanb: this is support for older configuration structs, newer peers should
                        **  send the peerClass value
                        */
                        {
                            // is the peer reporting it is a SysView peer?
                            if (peerConfig["sysView"].is<bool>()) {
                                bool sysView = peerConfig["sysView"].get<bool>();
                                if (sysView)
                                    LogInfoEx(LOG_MASTER, "PEER %u >> SysView Peer", peerId);
                            }
                        }

                        // determine the peer class (downstream FNE neighbor via externalPeer, or peerClass)
                        connection->peerClass(resolveOfferedPeerClass(peerConfig));

                        // is the peer reporting it is a conventional peer?
                        if (peerConfig["conventionalPeer"].is<bool>()) {
                            if (network->m_allowConvSiteAffOverride) {
                                bool convPeer = peerConfig["conventionalPeer"].get<bool>();
                                connection->isConventional(convPeer);
                            } else {
                                bool conventionalPeer = false;
                                peerConfig["conventionalPeer"].set<bool>(conventionalPeer);
                            }
                        } else {
                            bool conventionalPeer = false;
                            peerConfig["conventionalPeer"].set<bool>(conventionalPeer);
                        }

                        // report peer class in log
                        switch (connection->peerClass()) {
                            case PEER_CONN_CLASS_NEIGHBOR:
                                LogInfoEx(LOG_MASTER, "PEER %u >> Downstream Neighbor FNE Peer", peerId);
                                break;
                            case PEER_CONN_CLASS_SYSVIEW:
                                LogInfoEx(LOG_MASTER, "PEER %u >> SysView Peer", peerId);
                                connection->isReplica(true);
                                break;
                            case PEER_CONN_CLASS_CONSOLE:
                                LogInfoEx(LOG_MASTER, "PEER %u >> Console Peer", peerId);
                                break;
                            case PEER_CONN_CLASS_STANDARD:
                            default:
                                if (connection->isConventional())
                                    LogInfoEx(LOG_MASTER, "PEER %u >> Conventional Peer", peerId);
                                else
                                    LogInfoEx(LOG_MASTER, "PEER %u >> Standard Peer", peerId);
                                break;
                        }

                        // for the purposes of maintaining backward compat with REST API users,
                        //  we will report the peer class via the old externalPeer and sysView boolean 
                        //  fields as well (consolePeer doesn't have a legacy field, but that's ok since 
                        //  it's only used for console connections which should be new enough to support 
                        //  the new peerClass field)
                        bool externalPeer = connection->peerClass() == PEER_CONN_CLASS_NEIGHBOR;
                        peerConfig["externalPeer"].set<bool>(externalPeer);
                        bool sysViewPeer = connection->peerClass() == PEER_CONN_CLASS_SYSVIEW;
                        peerConfig["sysView"].set<bool>(sysViewPeer);
                        bool consolePeer = connection->peerClass() == PEER_CONN_CLASS_CONSOLE;
                        peerConfig["consolePeer"].set<bool>(consolePeer);
                        connection->config(peerConfig);

                        // is the peer reporting it is an downstream FNE neighbor peer?
                        /*
                        ** bryanb: don't change externalPeer to neighborPeer -- this will break backward
                        **  compat with older FNE versions (we're stuck with this naming :()
                        */
                        if (connection->peerClass() == PEER_CONN_CLASS_NEIGHBOR) {
                            uint32_t masterPeerId = 0U;
                            if (peerConfig["masterPeerId"].is<uint32_t>()) {
                                masterPeerId = peerConfig["masterPeerId"].get<uint32_t>();
                                connection->masterId(masterPeerId);
                                LogInfoEx(LOG_MASTER, "PEER %u >> Master Peer ID [%u]", peerId, masterPeerId);
                            }

                            // master peer ID should never be zero for an neighbor peer -- use the peer ID instead
                            if (masterPeerId == 0U) {
                                LogWarning(LOG_MASTER, "PEER %u reports to be a downstream FNE neighbor peer but has not supplied a valid masterPeerId, using own peerId as masterPeerId (old FNE perhaps?)", peerId);
                                masterPeerId = peerId;
                            }

                            // check if the peer a peer replication participant
                            lookups::PeerId peerEntry = network->m_peerListLookup->find(req->peerId);
                            if (!peerEntry.peerDefault()) {
                                if (peerEntry.peerReplica()) {
                                    connection->isReplica(true);
                                    LogInfoEx(LOG_MASTER, "PEER %u >> Participates in Peer Replication", peerId);
                                }
                            }

                            if (network->m_enableSpanningTree) {
                                network->m_treeLock.lock();

                                // check if this peer is already connected via another peer
                                SpanningTree* tree = SpanningTree::findByMasterID(masterPeerId);
                                if (tree != nullptr) {
                                    // are we allowing a fast reconnect? (this happens when a connecting peer
                                    //  uses the same peer ID and master ID already announced in the tree, but
                                    //  the tree entry wasn't yet erased)
                                    if ((tree->id() == peerId && tree->masterId() == masterPeerId) &&
                                        network->m_spanningTreeFastReconnect) {
                                        LogWarning(LOG_STP, "PEER %u (%s) server already announced in server tree, fast peer reconnect, peerId = %u, masterId = %u, treePeerId = %u, treeMasterId = %u, connectionState = %u", peerId, connection->identWithQualifier().c_str(),
                                            peerId, masterPeerId, tree->id(), tree->masterId(), connection->connectionState());
                                        if (identity != tree->identity()) {
                                            LogWarning(LOG_STP, "PEER %u (%s) why has this server's announced identity changed? *big hmmmm*", peerId, connection->identWithQualifier().c_str());
                                        }
                                        SpanningTree::moveParent(tree, network->m_treeRoot);
                                        network->logSpanningTree(connection.get());
                                    } else {
                                        LogWarning(LOG_STP, "PEER %u (%s) RPTC NAK, server already connected via PEER %u, duplicate connection denied, peerId = %u, masterId = %u, treePeerId = %u, treeMasterId = %u, connectionState = %u", peerId, connection->identWithQualifier().c_str(),
                                            peerId, masterPeerId, tree->id(), tree->masterId(), tree->id(), connection->connectionState());
                                        network->writePeerNAK(peerId, TAG_REPEATER_CONFIG, NET_CONN_NAK_FNE_DUPLICATE_CONN, req->address, req->addrLen);
                                        network->m_treeLock.unlock();
                                        network->disconnectPeer(peerId, connection);
                                        return;
                                    }
                                } else {
                                    SpanningTree* node = new SpanningTree(peerId, masterPeerId, network->m_treeRoot);
                                    node->identity(identity);
                                    network->logSpanningTree(connection.get());
                                }

                                network->m_treeLock.unlock();
                            }
                        }

                        // P25 roaming link state for the mobility service (spec 2.3, 2.4); raised before the ACK is
                        //  written so a ROAMING frame sent right after the ACK finds the link negotiated
                        RoamingLink roamingLink;
                        roamingLink.peerId = peerId;
                        roamingLink.upstream = false;
                        network->m_roaming->linkUp(roamingLink, roamingLogin == RoamingLogin::CAPABLE, neighborOffer,
                            peerRoaming.netId, peerRoaming.sysId);

                        network->writePeerACK(peerId, streamId, buffer, ackLength);
                        LogInfoEx(LOG_MASTER, "PEER %u RPTC ACK, completed the configuration exchange", peerId);

                        // setup the affiliations list for this peer
                        std::stringstream peerName;
                        peerName << "PEER " << peerId;
                        network->createPeerAffiliations(peerId, peerName.str());

                        // spin up a thread and send metadata over to peer
                        network->peerMetadataUpdate(peerId);
                        if (network->patchStatusEnabled() && connection->peerClass() == PEER_CONN_CLASS_CONSOLE)
                            network->writePatchStatusToPeer(peerId, network->patchStatusRegistry().snapshot());
                    }
                }
            }
            else {
                // perform source address/port validation
                if (connection->address() != udp::Socket::address(req->address) ||
                    connection->port() != udp::Socket::port(req->address)) {
                    LogError(LOG_MASTER, "PEER %u (%s) RPTC NAK, IP address/port mismatch on RPTC attempt while in an incorrect state, old = %s:%u, new = %s:%u, connectionState = %u", peerId, connection->identWithQualifier().c_str(),
                        connection->address().c_str(), connection->port(), udp::Socket::address(req->address).c_str(), udp::Socket::port(req->address), connection->connectionState());

                    network->writePeerNAK(peerId, TAG_REPEATER_LOGIN, NET_CONN_NAK_FNE_UNAUTHORIZED, req->address, req->addrLen);
                    return;
                }

                LogWarning(LOG_MASTER, "PEER %u (%s) RPTC NAK, login exchange while in an incorrect state, connectionState = %u", peerId, connection->identWithQualifier().c_str(),
                    connection->connectionState());
                network->writePeerNAK(peerId, TAG_REPEATER_CONFIG, NET_CONN_NAK_BAD_CONN_STATE, req->address, req->addrLen);
                network->disconnectPeer(peerId, connection);
            }
        }
    }
    else {
        network->writePeerNAK(peerId, TAG_REPEATER_CONFIG, NET_CONN_NAK_BAD_CONN_STATE, req->address, req->addrLen);
        LogWarning(LOG_MASTER, "PEER %u RPTC NAK, having no connection", peerId);
    }
}
