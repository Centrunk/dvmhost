// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Converged FNE Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "fne/network/RoamingService.h"
#include "common/network/RTPFNEHeader.h"
#include "common/Log.h"

using namespace network;
using namespace network::roaming;

#include <cassert>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the RoamingService class. */

RoamingService::RoamingService(RoamingServiceHost* host) :
    m_host(host),
    m_mutex(),
    m_netId(0U),
    m_sysId(0U),
    m_expires(ROAM_DEFAULT_EXPIRES),
    m_links(),
    m_systems(),
    m_upstreamDefault(),
    m_home(),
    m_serving(),
    m_pending(),
    m_random()
{
    assert(host != nullptr);

    std::random_device rd;
    m_random.seed(rd());
}

/* Sets this FNE's system identity. */

void RoamingService::setIdentity(uint32_t netId, uint32_t sysId, uint32_t expires)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_netId = netId;
    m_sysId = sysId;
    m_expires = expires;
}

/* Gets whether the service has a system identity. */

bool RoamingService::enabled() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_netId != 0U && m_sysId != 0U;
}

/* Records a link that completed login. */

void RoamingService::linkUp(const RoamingLink& link, bool capable, bool fne, uint32_t netId, uint32_t sysId)
{
    if (!link.valid()) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Each SU has one Home RFSS (BACA 2.1.3.1.1), found from the WACN ID and System ID of its SUID, so exactly one FNE
    // per system holds the identity; an FNE link (upstream master or downstream FNE) carrying it would be a second home.
    if (capable && fne && isOwnSystem(netId, sysId)) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u FNE carries this system's own identity, netId = $%05X, sysId = $%03X, link is not roaming capable",
            linkName(link), link.peerId, netId, sysId);
        capable = false;
    }

    // a reconnecting link may carry a new identity
    for (auto it = m_systems.begin(); it != m_systems.end();) {
        if (it->second == link) {
            it = m_systems.erase(it);
        }
        else {
            ++it;
        }
    }

    LinkState state;
    state.link = link;
    state.capable = capable;
    state.fne = fne;
    state.netId = netId;
    state.sysId = sysId;
    m_links[link.key()] = state;

    // each FNE keeps a table (WACN, System ID) -> peer link
    if (capable && fne && netId != 0U && sysId != 0U && !isOwnSystem(netId, sysId)) {
        m_systems[SUID::systemKey(netId, sysId)] = link;
    }

    if (capable && link.upstream && !m_upstreamDefault.valid()) {
        m_upstreamDefault = link;
    }
    else if (!capable && m_upstreamDefault == link) {
        // the default upstream reconnected without roaming
        selectUpstreamDefault();
    }

    // links that did not negotiate roaming stay silent
    if (capable) {
        LogInfoEx(LOG_MASTER, "P25 ROAMING, %s %u link up, capable = %u, fne = %u, netId = $%05X, sysId = $%03X", linkName(link),
            link.peerId, capable ? 1U : 0U, fne ? 1U : 0U, netId, sysId);
    }
}

/* Removes a link. */

void RoamingService::linkDown(const RoamingLink& link)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_links.erase(link.key()) == 0U) {
        return;
    }

    for (auto it = m_systems.begin(); it != m_systems.end();) {
        if (it->second == link) {
            it = m_systems.erase(it);
        }
        else {
            ++it;
        }
    }

    if (m_upstreamDefault == link) {
        selectUpstreamDefault();
    }

    // transactions using the link complete as FAILED; FAILED is never sent on the wire
    uint32_t failed = 0U;
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        if (it->first.first == link.key() || it->second.ingress == link) {
            ++failed;
            it = m_pending.erase(it);
        }
        else {
            ++it;
        }
    }

    for (auto it = m_serving.begin(); it != m_serving.end();) {
        if (it->second.link == link) {
            it = m_serving.erase(it);
        }
        else {
            ++it;
        }
    }

    // home records stay until expires
    if (failed > 0U) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u link down, %u pending transaction(s) completed as FAILED", linkName(link), link.peerId, failed);
    }
    else {
        LogDebug(LOG_MASTER, "P25 ROAMING, %s %u link down", linkName(link), link.peerId);
    }
}

/* Gets whether a link negotiated P25 roaming. */

bool RoamingService::isLinkCapable(const RoamingLink& link) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return linkCapableLocked(link);
}

/* Processes one ROAMING message received on a link. */

void RoamingService::process(const RoamingLink& ingress, uint8_t subFunc, const uint8_t* data, uint32_t length, uint64_t nowMs)
{
    if (data == nullptr || length == 0U) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u malformed message, subFunc = $%02X, dropped", linkName(ingress), ingress.peerId, subFunc);
        return;
    }

    if (!enabled() || !isLinkCapable(ingress)) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u did not negotiate P25 roaming, subFunc = $%02X, dropped", linkName(ingress),
            ingress.peerId, subFunc);
        return;
    }

    ActionList actions;

    // an unknown request is answered GEN_PROC_UNSUPPORTED; an unknown response is dropped (BACA 5.5 Gen Req 4-5)
    if (Roaming::messageLength(subFunc) == 0U) {
        uint8_t version = 0U;
        uint8_t hopCount = 0U;
        uint32_t txnId = 0U;
        if (Roaming::isRequest(subFunc) && Roaming::decodeHeader(data, length, version, hopCount, txnId) == RoamDecode::OK &&
            version == ROAM_VERSION) {
            LogWarning(LOG_MASTER, "P25 ROAMING, %s %u unsupported request subFunc = $%02X, txnId = %08X, answered GEN_PROC_UNSUPPORTED",
                linkName(ingress), ingress.peerId, subFunc, txnId);
            RoamingMessage rsp;
            rsp.subFunc = NET_SUBFUNC::ROAM_GEN_RSP;
            rsp.txnId = txnId;
            rsp.rejectedSubFunc = subFunc;
            rsp.result = RoamResult::GEN_PROC_UNSUPPORTED;
            queueSend(actions, ingress, rsp);
        }
        else {
            LogWarning(LOG_MASTER, "P25 ROAMING, %s %u unknown response subFunc = $%02X, dropped", linkName(ingress), ingress.peerId, subFunc);
        }

        runActions(actions);
        return;
    }

    RoamingMessage msg;
    const RoamDecode::E status = Roaming::decode(subFunc, data, length, msg);
    if (status != RoamDecode::OK) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u malformed message, subFunc = $%02X, length = %u, status = %u, dropped",
            linkName(ingress), ingress.peerId, subFunc, length, (uint32_t)status);
        return;
    }

    if (msg.hopCount == 0U) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u hop count exhausted, subFunc = $%02X, txnId = %08X, dropped", linkName(ingress),
            ingress.peerId, subFunc, msg.txnId);
        return;
    }

    // home authorization lookups take their own locks, so they run before the service lock
    bool authorized = false;
    uint32_t localPeer = 0U;
    if (msg.subFunc == NET_SUBFUNC::ROAM_SERVING_REG) {
        bool own = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            own = isOwnSystem(msg.suid.netId, msg.suid.sysId);
        }

        if (own) {
            authorized = m_host->isHomeUnitAuthorized(msg.suid.unitId);
            localPeer = m_host->findLocalUnitPeer(msg.suid.unitId);
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (Roaming::isRequest(msg.subFunc)) {
            handleRequest(actions, ingress, msg, nowMs, authorized, localPeer);
        }
        else {
            handleResponse(actions, ingress, msg, nowMs);
        }
    }

    runActions(actions);
}

/* Expires forwarded transactions and home records. */

void RoamingService::clock(uint64_t nowMs)
{
    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            if (nowMs >= it->second.startedMs && nowMs - it->second.startedMs >= ROAM_FNE_PENDING_TIMEOUT_MS) {
                const SUID suid = SUID::unpack(it->second.suid);
                LogWarning(LOG_MASTER, "P25 ROAMING, %s %u subFunc = $%02X, suid = $%05X.$%03X.$%06X, txnId = %08X expired without a response, completed as FAILED",
                    linkName(it->second.egress), it->second.egress.peerId, it->second.subFunc, suid.netId, suid.sysId, suid.unitId, it->first.second);
                it = m_pending.erase(it);
            }
            else {
                ++it;
            }
        }

        for (auto it = m_home.begin(); it != m_home.end();) {
            if (nowMs >= it->second.expiresAtMs) {
                const HomeRecord rec = it->second;
                LogInfoEx(LOG_MASTER, "P25 ROAMING, home registration expired, suid = $%05X.$%03X.$%06X", rec.suid.netId, rec.suid.sysId,
                    rec.suid.unitId);
                RoamingServiceHost* host = m_host;
                actions.push_back([host, rec]() { host->eraseUnitRoute(rec.suid, rec.link); });
                it = m_home.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    runActions(actions);
}

/* Sends Non-Roamed Home Deregistration for home records whose unit is no longer authorized. */

void RoamingService::revalidateHomeRecords(uint64_t nowMs)
{
    // RID ACL lookups take their own lock, so authorization is evaluated outside the service lock
    std::vector<uint64_t> revoked;
    for (const HomeRecord& rec : homeRecords()) {
        if (!m_host->isHomeUnitAuthorized(rec.suid.unitId)) {
            revoked.push_back(rec.suid.pack());
        }
    }

    if (revoked.empty()) {
        return;
    }

    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (uint64_t key : revoked) {
            auto it = m_home.find(key);
            if (it == m_home.end()) {
                continue;
            }

            const HomeRecord rec = it->second;
            m_home.erase(it);
            LogWarning(LOG_MASTER, "P25 ROAMING, home unit no longer authorized, Non-Roamed Home Deregistration, suid = $%05X.$%03X.$%06X",
                rec.suid.netId, rec.suid.sysId, rec.suid.unitId);
            sendHomeDereg(actions, rec.link, rec.suid, RoamQualifier::NON_ROAMED, nowMs);
            RoamingServiceHost* host = m_host;
            actions.push_back([host, rec]() { host->eraseUnitRoute(rec.suid, rec.link); });
        }
    }

    runActions(actions);
}

/* Handles a home SU registering on one of this system's own sites. */

void RoamingService::localRegistration(uint32_t unitId, uint64_t nowMs)
{
    if (unitId > ROAM_MAX_UNIT_ID) {
        return;
    }

    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_netId == 0U || m_sysId == 0U) {
            return;
        }

        SUID suid;
        suid.netId = m_netId;
        suid.sysId = m_sysId;
        suid.unitId = unitId;
        auto it = m_home.find(suid.pack());
        if (it == m_home.end()) {
            return;
        }

        const HomeRecord rec = it->second;
        m_home.erase(it);
        LogInfoEx(LOG_MASTER, "P25 ROAMING, home unit registered on a home site, Roamed Home Deregistration to $%05X.$%03X RFSS $%02X, suid = $%05X.$%03X.$%06X",
            rec.serving.netId, rec.serving.sysId, rec.serving.rfssId, rec.suid.netId, rec.suid.sysId, rec.suid.unitId);
        sendHomeDereg(actions, rec.link, rec.suid, RoamQualifier::ROAMED, nowMs);
        RoamingServiceHost* host = m_host;
        actions.push_back([host, rec]() { host->eraseUnitRoute(rec.suid, rec.link); });
    }

    runActions(actions);
}

/* Sends a Forced query to the serving RFSS of a home SU. */

bool RoamingService::forcedQuery(const SUID& suid, uint64_t nowMs)
{
    if (!suid.valid()) {
        return false;
    }

    ActionList actions;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_home.find(suid.pack());
        if (it == m_home.end()) {
            return false;
        }

        const RoamingLink link = it->second.link;
        RoamingMessage query;
        query.subFunc = NET_SUBFUNC::ROAM_QUERY;
        query.txnId = nextTxnId(link);
        query.suid = suid;
        query.queryType = RoamQueryType::FORCED;

        Pending pending;
        pending.egress = link;
        pending.subFunc = query.subFunc;
        pending.suid = suid.pack();
        pending.startedMs = nowMs;
        m_pending[std::make_pair(link.key(), query.txnId)] = pending;

        LogInfoEx(LOG_MASTER, "P25 ROAMING, Forced query to %s %u, suid = $%05X.$%03X.$%06X, txnId = %08X", linkName(link), link.peerId,
            suid.netId, suid.sysId, suid.unitId, query.txnId);
        queueSend(actions, link, query);
    }

    runActions(actions);
    return true;
}

/* Gets a copy of the home location table. */

std::vector<RoamingService::HomeRecord> RoamingService::homeRecords() const
{
    std::vector<HomeRecord> records;
    std::lock_guard<std::mutex> lock(m_mutex);
    records.reserve(m_home.size());
    for (const auto& entry : m_home) {
        records.push_back(entry.second);
    }
    return records;
}

/* Gets a copy of the served-roamer table. */

std::vector<RoamingService::ServingRecord> RoamingService::servingRecords() const
{
    std::vector<ServingRecord> records;
    std::lock_guard<std::mutex> lock(m_mutex);
    records.reserve(m_serving.size());
    for (const auto& entry : m_serving) {
        records.push_back(entry.second);
    }
    return records;
}

/* Gets the number of open transactions. */

size_t RoamingService::pendingCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.size();
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Checks a WACN ID and System ID against this system. */

bool RoamingService::isOwnSystem(uint32_t netId, uint32_t sysId) const
{
    return m_netId != 0U && m_sysId != 0U && netId == m_netId && sysId == m_sysId;
}

/* Checks whether a link's far end is an FNE. */

bool RoamingService::linkIsFne(const RoamingLink& link) const
{
    auto it = m_links.find(link.key());
    return it != m_links.end() && it->second.fne;
}

/* Checks whether a link negotiated roaming. */

bool RoamingService::linkCapableLocked(const RoamingLink& link) const
{
    auto it = m_links.find(link.key());
    return it != m_links.end() && it->second.capable;
}

/* Chooses a new upstream default among capable upstream links. */

void RoamingService::selectUpstreamDefault()
{
    m_upstreamDefault = RoamingLink();
    for (const auto& entry : m_links) {
        if (entry.second.capable && entry.second.link.upstream &&
            (!m_upstreamDefault.valid() || entry.second.link.peerId < m_upstreamDefault.peerId)) {
            m_upstreamDefault = entry.second.link;
        }
    }
}

/* Generates a transaction ID for a request originated here. */

uint32_t RoamingService::nextTxnId(const RoamingLink& link)
{
    // a forwarded transaction toward the same link must never be overwritten
    std::uniform_int_distribution<uint32_t> dist(1U, 0xFFFFFFFFU);
    uint32_t txnId = dist(m_random);
    while (m_pending.find(std::make_pair(link.key(), txnId)) != m_pending.end()) {
        txnId = dist(m_random);
    }

    return txnId;
}

/* Encodes a message and queues its send. */

void RoamingService::queueSend(ActionList& actions, const RoamingLink& link, const RoamingMessage& msg) const
{
    uint8_t buffer[MSG_ROAM_MAX_LEN];
    const uint32_t length = Roaming::encode(msg, buffer, sizeof(buffer));
    if (length == 0U) {
        LogError(LOG_MASTER, "P25 ROAMING, failed to encode subFunc = $%02X, txnId = %08X", msg.subFunc, msg.txnId);
        return;
    }

    RoamingServiceHost* host = m_host;
    const uint8_t subFunc = msg.subFunc;
    const std::vector<uint8_t> bytes(buffer, buffer + length);
    actions.push_back([host, link, subFunc, bytes]() { host->sendRoaming(link, subFunc, bytes.data(), (uint32_t)bytes.size()); });
}

/* Queues the response to a request with a result. */

void RoamingService::queueReply(ActionList& actions, const RoamingLink& link, const RoamingMessage& request, uint8_t result) const
{
    RoamingMessage rsp;
    rsp.subFunc = (uint8_t)(request.subFunc + 1U);
    rsp.txnId = request.txnId;
    rsp.suid = request.suid;
    rsp.result = result;

    LogInfoEx(LOG_MASTER, "P25 ROAMING, %s %u response subFunc = $%02X, suid = $%05X.$%03X.$%06X, txnId = %08X, result = $%02X",
        linkName(link), link.peerId, rsp.subFunc, rsp.suid.netId, rsp.suid.sysId, rsp.suid.unitId, rsp.txnId, result);
    queueSend(actions, link, rsp);
}

/* Builds the home's success response to a Serving Registration. */

RoamingMessage RoamingService::successResponse(const RoamingMessage& request) const
{
    RoamingMessage rsp;
    rsp.subFunc = NET_SUBFUNC::ROAM_SERVING_REG_RSP;
    rsp.txnId = request.txnId;
    rsp.suid = request.suid;
    rsp.result = RoamResult::SUCCESS;
    rsp.expires = m_expires;
    rsp.access = RoamAccess::FULL;
    rsp.flags = 0x00U;
    return rsp;
}

/* Dispatches a decoded request. */

void RoamingService::handleRequest(ActionList& actions, const RoamingLink& ingress, const RoamingMessage& msg, uint64_t nowMs,
    bool authorized, uint32_t localPeer)
{
    switch (msg.subFunc) {
    case NET_SUBFUNC::ROAM_SERVING_REG:
        if (isOwnSystem(msg.suid.netId, msg.suid.sysId)) {
            handleHomeServingReg(actions, ingress, msg, nowMs, authorized, localPeer);
        }
        else {
            forwardTowardHome(actions, ingress, msg, nowMs);
        }
        break;
    case NET_SUBFUNC::ROAM_SERVING_DEREG:
        if (isOwnSystem(msg.suid.netId, msg.suid.sysId)) {
            handleHomeServingDereg(actions, ingress, msg);
        }
        else {
            // the roamer is no longer served behind the ingress link
            auto it = m_serving.find(msg.suid.pack());
            if (it != m_serving.end() && it->second.link == ingress) {
                m_serving.erase(it);
            }

            forwardTowardHome(actions, ingress, msg, nowMs);
        }
        break;
    case NET_SUBFUNC::ROAM_HOME_DEREG:
    case NET_SUBFUNC::ROAM_QUERY:
        // Home Deregistration and Query travel from the home toward the serving host, so at an FNE they arrive only
        // on links facing the home (FNE links); a host link never originates them.
        if (!linkIsFne(ingress)) {
            LogWarning(LOG_MASTER, "P25 ROAMING, %s %u host link sent subFunc = $%02X, suid = $%05X.$%03X.$%06X, txnId = %08X, dropped",
                linkName(ingress), ingress.peerId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
            break;
        }

        forwardTowardServing(actions, ingress, msg, nowMs);
        break;
    default:
        break;
    }
}

/* Home handling of a Serving Registration. */

void RoamingService::handleHomeServingReg(ActionList& actions, const RoamingLink& ingress, const RoamingMessage& msg, uint64_t nowMs,
    bool authorized, uint32_t localPeer)
{
    const uint64_t key = msg.suid.pack();
    auto existing = m_home.find(key);

    // a duplicate of an accepted request gets the same answer and changes nothing
    if (existing != m_home.end() && existing->second.lastTxnId == msg.txnId && existing->second.link == ingress) {
        LogInfoEx(LOG_MASTER, "P25 ROAMING, %s %u duplicate Serving Registration, suid = $%05X.$%03X.$%06X, txnId = %08X, answered SUCCESS",
            linkName(ingress), ingress.peerId, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        queueSend(actions, ingress, successResponse(msg));
        return;
    }

    if (!authorized) {
        LogWarning(LOG_MASTER, "P25 ROAMING, Serving Registration denied, home unit not in the RID ACL or disabled, suid = $%05X.$%03X.$%06X, txnId = %08X",
            msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        queueReply(actions, ingress, msg, RoamResult::MME_SU_UNKNOWN);
        return;
    }

    // A Serving Registration with presence Not Confirmed (a timer refresh or resync) for an SU the home records at a
    // different serving RFSS must confirm presence; the record stays, so a serving RFSS that missed its Home
    // Deregistration cannot take the SU back from the RFSS that holds it (BACA 5.5.1(2b)).
    if (existing != m_home.end() && msg.presence == RoamPresence::NOT_CONFIRMED && !(existing->second.serving == msg.serving)) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u Serving Registration presence Not Confirmed from $%05X.$%03X RFSS $%02X, served by $%05X.$%03X RFSS $%02X, suid = $%05X.$%03X.$%06X, txnId = %08X, answered MME_MUST_CONFIRM_SU_PRESENCE",
            linkName(ingress), ingress.peerId, msg.serving.netId, msg.serving.sysId, msg.serving.rfssId, existing->second.serving.netId,
            existing->second.serving.sysId, existing->second.serving.rfssId, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        queueReply(actions, ingress, msg, RoamResult::MME_MUST_CONFIRM_SU_PRESENCE);
        return;
    }

    const bool hadPrevious = (existing != m_home.end());
    HomeRecord previous;
    if (hadPrevious) {
        previous = existing->second;
    }

    HomeRecord rec;
    rec.suid = msg.suid;
    rec.serving = msg.serving;
    rec.link = ingress;
    rec.expiresAtMs = nowMs + ((uint64_t)m_expires * 1000U);
    rec.lastTxnId = msg.txnId;
    m_home[key] = rec;

    LogInfoEx(LOG_MASTER, "P25 ROAMING, Serving Registration accepted, suid = $%05X.$%03X.$%06X, serving = $%05X.$%03X RFSS $%02X, txnId = %08X, expires = %us",
        msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.serving.netId, msg.serving.sysId, msg.serving.rfssId, msg.txnId, m_expires);
    queueSend(actions, ingress, successResponse(msg));

    // A unit is registered at only one serving RFSS at a time (BACA 5.1, 5.5.1(2a)(iii)). The home deregisters the
    // previous serving RFSS only when it sits behind a different link. When both sit behind the same link, the
    // success and a Home Deregistration would share that link and could arrive in either order (UDP), so the
    // downstream FNE whose served-roamer record changes link deregisters the previous RFSS instead (handleResponse).
    if (hadPrevious && previous.link != ingress) {
        sendHomeDereg(actions, previous.link, msg.suid, RoamQualifier::ROAMED, nowMs);
    }

    // internal silent Roamed deregistration of the home's own site
    if (localPeer != 0U) {
        RoamingLink site;
        site.peerId = localPeer;
        site.upstream = false;
        if (linkCapableLocked(site)) {
            sendHomeDereg(actions, site, msg.suid, RoamQualifier::ROAMED, nowMs);
        }

        RoamingServiceHost* host = m_host;
        const uint32_t unitId = msg.suid.unitId;
        actions.push_back([host, localPeer, unitId]() { host->removeLocalUnitRegistration(localPeer, unitId); });
    }

    RoamingServiceHost* host = m_host;
    const SUID suid = msg.suid;
    actions.push_back([host, suid, ingress]() { host->setUnitRoute(suid, ingress); });
}

/* Home handling of a Serving Deregistration. */

void RoamingService::handleHomeServingDereg(ActionList& actions, const RoamingLink& ingress, const RoamingMessage& msg)
{
    // the serving RFSS identity in the message is only trusted on the link the home record was learned from
    auto it = m_home.find(msg.suid.pack());
    if (it == m_home.end() || !(it->second.serving == msg.serving) || !(it->second.link == ingress)) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u Serving Deregistration from a non-serving RFSS $%05X.$%03X RFSS $%02X or link, suid = $%05X.$%03X.$%06X, txnId = %08X",
            linkName(ingress), ingress.peerId, msg.serving.netId, msg.serving.sysId, msg.serving.rfssId, msg.suid.netId, msg.suid.sysId,
            msg.suid.unitId, msg.txnId);
        queueReply(actions, ingress, msg, RoamResult::MME_OBJ_NOT_REG_AT_SERV);
        return;
    }

    const HomeRecord rec = it->second;
    m_home.erase(it);

    RoamingServiceHost* host = m_host;
    actions.push_back([host, rec]() { host->eraseUnitRoute(rec.suid, rec.link); });
    queueReply(actions, ingress, msg, RoamResult::SUCCESS);
}

/* Forwards a request toward the SU's home system. */

void RoamingService::forwardTowardHome(ActionList& actions, const RoamingLink& ingress, const RoamingMessage& msg, uint64_t nowMs)
{
    RoamingLink egress;
    auto sys = m_systems.find(SUID::systemKey(msg.suid.netId, msg.suid.sysId));
    if (sys != m_systems.end()) {
        egress = sys->second;
    }
    else if (m_upstreamDefault.valid()) {
        egress = m_upstreamDefault;
    }

    if (!egress.valid() || egress == ingress) {
        if (linkIsFne(ingress)) {
            LogWarning(LOG_MASTER, "P25 ROAMING, %s %u subFunc = $%02X, no route toward the home system, suid = $%05X.$%03X.$%06X, txnId = %08X, answered MME_SU_UNKNOWN",
                linkName(ingress), ingress.peerId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
            queueReply(actions, ingress, msg, RoamResult::MME_SU_UNKNOWN);
        }
        else {
            LogWarning(LOG_MASTER, "P25 ROAMING, %s %u subFunc = $%02X, no route toward the home system, suid = $%05X.$%03X.$%06X, txnId = %08X, completes as FAILED at the host",
                linkName(ingress), ingress.peerId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        }
        return;
    }

    forward(actions, ingress, egress, msg, nowMs);
}

/* Forwards a request toward the SU's serving host. */

void RoamingService::forwardTowardServing(ActionList& actions, const RoamingLink& ingress, const RoamingMessage& msg, uint64_t nowMs)
{
    auto it = m_serving.find(msg.suid.pack());
    if (it == m_serving.end() || it->second.link == ingress) {
        // Not Found (BACA 2.1.4.1.3)
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u subFunc = $%02X for an SU not served behind another link, suid = $%05X.$%03X.$%06X, txnId = %08X, answered MME_SU_UNKNOWN",
            linkName(ingress), ingress.peerId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        queueReply(actions, ingress, msg, RoamResult::MME_SU_UNKNOWN);
        return;
    }

    forward(actions, ingress, it->second.link, msg, nowMs);
}

/* Forwards a request on an egress link and opens a transaction. */

void RoamingService::forward(ActionList& actions, const RoamingLink& ingress, const RoamingLink& egress, const RoamingMessage& msg, uint64_t nowMs)
{
    if (msg.hopCount <= 1U) {
        LogWarning(LOG_MASTER, "P25 ROAMING, hop count exhausted forwarding subFunc = $%02X, txnId = %08X, dropped", msg.subFunc, msg.txnId);
        return;
    }

    const std::pair<uint64_t, uint32_t> key = std::make_pair(egress.key(), msg.txnId);
    if (m_pending.find(key) != m_pending.end()) {
        LogWarning(LOG_MASTER, "P25 ROAMING, duplicate transaction txnId = %08X toward %s %u, dropped", msg.txnId, linkName(egress), egress.peerId);
        return;
    }

    Pending pending;
    pending.ingress = ingress;
    pending.egress = egress;
    pending.subFunc = msg.subFunc;
    pending.suid = msg.suid.pack();
    pending.startedMs = nowMs;
    m_pending[key] = pending;

    RoamingMessage fwd = msg;
    fwd.hopCount = (uint8_t)(msg.hopCount - 1U);
    LogInfoEx(LOG_MASTER, "P25 ROAMING, forward subFunc = $%02X from %s %u to %s %u, suid = $%05X.$%03X.$%06X, txnId = %08X", msg.subFunc,
        linkName(ingress), ingress.peerId, linkName(egress), egress.peerId, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
    queueSend(actions, egress, fwd);
}

/* Sends a Home Deregistration originated here and opens its transaction. */

void RoamingService::sendHomeDereg(ActionList& actions, const RoamingLink& link, const SUID& suid, uint8_t qualifier, uint64_t nowMs)
{
    RoamingMessage dereg;
    dereg.subFunc = NET_SUBFUNC::ROAM_HOME_DEREG;
    dereg.txnId = nextTxnId(link);
    dereg.suid = suid;
    dereg.qualifier = qualifier;

    Pending pending;
    pending.egress = link;
    pending.subFunc = dereg.subFunc;
    pending.suid = suid.pack();
    pending.startedMs = nowMs;
    m_pending[std::make_pair(link.key(), dereg.txnId)] = pending;

    LogInfoEx(LOG_MASTER, "P25 ROAMING, Home Deregistration (%s) to %s %u, suid = $%05X.$%03X.$%06X, txnId = %08X",
        (qualifier == RoamQualifier::ROAMED) ? "Roamed" : "Non-Roamed", linkName(link), link.peerId, suid.netId, suid.sysId, suid.unitId, dereg.txnId);
    queueSend(actions, link, dereg);
}

/* Matches and relays (or consumes) a response. */

void RoamingService::handleResponse(ActionList& actions, const RoamingLink& from, const RoamingMessage& msg, uint64_t nowMs)
{
    auto it = m_pending.find(std::make_pair(from.key(), msg.txnId));
    if (it == m_pending.end()) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u response with unknown or stale txnId = %08X, subFunc = $%02X, suid = $%05X.$%03X.$%06X, dropped",
            linkName(from), from.peerId, msg.txnId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId);
        return;
    }

    const Pending pending = it->second;
    const bool matches = (msg.subFunc == NET_SUBFUNC::ROAM_GEN_RSP) ? (msg.rejectedSubFunc == pending.subFunc) :
        (msg.subFunc == (uint8_t)(pending.subFunc + 1U) && msg.suid.pack() == pending.suid);
    if (!matches) {
        LogWarning(LOG_MASTER, "P25 ROAMING, %s %u response subFunc = $%02X, suid = $%05X.$%03X.$%06X does not match txnId = %08X, dropped",
            linkName(from), from.peerId, msg.subFunc, msg.suid.netId, msg.suid.sysId, msg.suid.unitId, msg.txnId);
        return;
    }

    m_pending.erase(it);

    // A response to a request originated here completes the transaction. It never touches the served-roamer table,
    // so a late answer from a previous serving link cannot release the roamer's new record.
    if (!pending.ingress.valid()) {
        const SUID suid = SUID::unpack(pending.suid);
        LogInfoEx(LOG_MASTER, "P25 ROAMING, %s %u response subFunc = $%02X, suid = $%05X.$%03X.$%06X, txnId = %08X, result = $%02X", linkName(from),
            from.peerId, msg.subFunc, suid.netId, suid.sysId, suid.unitId, msg.txnId, msg.result);
        return;
    }

    // a response that cannot be relayed leaves the served-roamer table untouched; the host times out as FAILED
    if (msg.hopCount <= 1U) {
        LogWarning(LOG_MASTER, "P25 ROAMING, hop count exhausted relaying txnId = %08X, dropped", msg.txnId);
        return;
    }

    if (msg.subFunc == NET_SUBFUNC::ROAM_SERVING_REG_RSP && msg.result == RoamResult::SUCCESS) {
        // One serving RFSS at a time (BACA 5.1): the home deregisters a previous serving RFSS only across a different
        // link, so when the roamer's served record moves from one link of this FNE to another, this FNE deregisters
        // the previous serving side itself. A record already on the relay link means the previous RFSS is further
        // downstream, where the next FNE applies the same rule.
        auto served = m_serving.find(pending.suid);
        if (served != m_serving.end() && served->second.link != pending.ingress) {
            sendHomeDereg(actions, served->second.link, msg.suid, RoamQualifier::ROAMED, nowMs);
        }

        ServingRecord rec;
        rec.suid = msg.suid;
        rec.link = pending.ingress;
        m_serving[pending.suid] = rec;
    }
    else if (msg.subFunc == NET_SUBFUNC::ROAM_HOME_DEREG_RSP) {
        // only the record the Home Deregistration was forwarded on is released
        auto served = m_serving.find(pending.suid);
        if (served != m_serving.end() && served->second.link == from) {
            m_serving.erase(served);
        }
    }

    RoamingMessage fwd = msg;
    fwd.hopCount = (uint8_t)(msg.hopCount - 1U);
    LogInfoEx(LOG_MASTER, "P25 ROAMING, relay response subFunc = $%02X from %s %u to %s %u, txnId = %08X, result = $%02X", msg.subFunc,
        linkName(from), from.peerId, linkName(pending.ingress), pending.ingress.peerId, msg.txnId, msg.result);
    queueSend(actions, pending.ingress, fwd);
}

/* Runs deferred actions. */

void RoamingService::runActions(ActionList& actions)
{
    for (auto& action : actions) {
        action();
    }
    actions.clear();
}

/* Gets a log name for a link direction. */

const char* RoamingService::linkName(const RoamingLink& link)
{
    return link.upstream ? "UPSTREAM" : "PEER";
}
